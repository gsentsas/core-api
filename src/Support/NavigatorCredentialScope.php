<?php

namespace Fleetbase\Support;

use Fleetbase\Models\ApiCredential;
use Fleetbase\Models\User;
use Illuminate\Http\Request;
use Laravel\Sanctum\PersonalAccessToken;

/** A Navigator key bootstraps driver login; it never grants console/admin access. */
class NavigatorCredentialScope
{
    public static function isNavigator(ApiCredential $credential): bool
    {
        return $credential->purpose === 'navigator';
    }

    public static function valid(ApiCredential $credential): bool
    {
        if (!static::isNavigator($credential) || $credential->trashed()
            || !$credential->expires_at || $credential->hasExpired()
            || $credential->expires_at->gt(now()->addDays(7))) {
            return false;
        }
        $device = User::query()->find($credential->user_uuid);
        $issuer = User::query()->find($credential->issuer_user_uuid);

        return $device && $issuer
            && $device->type === 'navigator-device' && $device->status === 'active'
            && $issuer->type === 'admin' && $issuer->status === 'active'
            && $device->company_uuid === $credential->company_uuid
            && $issuer->company_uuid === $credential->company_uuid
            && $issuer->company && $issuer->company->uuid === $credential->company_uuid;
    }

    public static function allowsBootstrap(Request $request): bool
    {
        $action = $request->route()?->getActionName();
        $prefix = 'Fleetbase\\FleetOps\\Http\\Controllers\\Api\\v1\\';
        if ($request->isMethod('POST') && in_array($action, [
            $prefix . 'DriverController@login',
            $prefix . 'DriverController@loginWithPhone',
            $prefix . 'DriverController@verifyCode',
        ], true)) {
            // verifyCode also exposes account creation; provisioning cannot authorize it.
            return $request->input('for', 'driver_login') === 'driver_login';
        }

        return $request->isMethod('GET') && $action === $prefix . 'NavigatorController@getDriverOnboardSettings';
    }

    public static function parent(PersonalAccessToken $token): ?ApiCredential
    {
        return ApiCredential::withoutGlobalScopes()->where('uuid', $token->navigator_credential_uuid)->first();
    }

    /** Apply to every freshly minted or rotated driver token in a paired session. */
    public static function bindDriverToken(PersonalAccessToken $token): void
    {
        $credential = request()->attributes->get('navigator_credential');
        if (!$credential instanceof ApiCredential) {
            return;
        }
        $user = $token->tokenable;
        if (!static::valid($credential) || !$user instanceof User || $user->type !== 'driver'
            || $user->status !== 'active' || $user->company_uuid !== $credential->company_uuid) {
            $token->delete();
            throw new \RuntimeException('Navigator driver identity is not authorized.');
        }
        $token->forceFill([
            'navigator_credential_uuid' => $credential->uuid,
            'expires_at' => $credential->expires_at,
        ])->save();
    }
}
