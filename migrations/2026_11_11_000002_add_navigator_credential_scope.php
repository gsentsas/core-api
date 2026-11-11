<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('api_credentials', function (Blueprint $table): void {
            $table->string('purpose', 32)->nullable()->index();
            $table->string('issuer_user_uuid', 36)->nullable()->index();
        });
        Schema::table('personal_access_tokens', function (Blueprint $table): void {
            $table->string('navigator_credential_uuid', 36)->nullable()->index();
        });
    }

    public function down(): void
    {
        // A release rollback must revoke scoped credentials/tokens first.
        // Dropping their discriminator while they exist would broaden access.
        if (Schema::hasColumn('api_credentials', 'purpose')
            && \Illuminate\Support\Facades\DB::table('api_credentials')->where('purpose', 'navigator')->exists()) {
            throw new RuntimeException('Revoke and remove Navigator credentials before rolling back their scope schema.');
        }
        if (\Illuminate\Support\Facades\DB::table('personal_access_tokens')->whereNotNull('navigator_credential_uuid')->exists()) {
            throw new RuntimeException('Remove Navigator sessions before rolling back their scope schema.');
        }
        Schema::table('personal_access_tokens', fn (Blueprint $table) => $table->dropColumn('navigator_credential_uuid'));
        Schema::table('api_credentials', fn (Blueprint $table) => $table->dropColumn(['purpose', 'issuer_user_uuid']));
    }
};
