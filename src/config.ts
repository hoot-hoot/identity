import { Env, parseEnv, isOnServer } from '@truesparrow/common-js'
import { getFromEnv } from '@truesparrow/common-server-js'
import { Auth0ServerConfig } from '@truesparrow/identity-sdk-js'
import { config } from 'dotenv';

config();

// Common to all services

export const ENV: Env = parseEnv(getFromEnv('COMMON_ENV'));

export const LOGGLY_TOKEN: string | null = isOnServer(ENV) ? getFromEnv('COMMON_LOGGLY_TOKEN') : null;
export const LOGGLY_SUBDOMAIN: string | null = isOnServer(ENV) ? getFromEnv('COMMON_LOGGLY_SUBDOMAIN') : null;
export const ROLLBAR_TOKEN: string | null = isOnServer(ENV) ? getFromEnv('COMMON_ROLLBAR_TOKEN') : null;

// Specific to identity service

export const NAME: string = 'identity';
export const ADDRESS: string = getFromEnv('IDENTITY_ADDRESS');
export const PORT: number = parseInt(getFromEnv('IDENTITY_PORT'), 10);
export const ORIGIN: string = getFromEnv('IDENTITY_ORIGIN');

export const CLIENTS: string[] = getFromEnv('IDENTITY_CLIENTS').split(',');

export const DATABASE_URL: string = getFromEnv('IDENTITY_DATABASE_URL');
export const DATABASE_MIGRATIONS_DIR: string = getFromEnv('IDENTITY_DATABASE_MIGRATIONS_DIR');
export const DATABASE_MIGRATIONS_TABLE: string = getFromEnv('IDENTITY_DATABASE_MIGRATIONS_TABLE');

export const AUTH0_SERVER_CONFIG: Auth0ServerConfig = {
    clientId: getFromEnv('IDENTITY_AUTH0_CLIENT_ID'),
    clientSecret: getFromEnv('IDENTITY_AUTH0_CLIENT_SECRET'),
    domain: getFromEnv('IDENTITY_AUTH0_DOMAIN'),
    loginCallbackUri: '' // Not used here
};
export const AUTH0_CACHE_TTL_IN_SECS: number = 10 * 60; // 10 minutes
