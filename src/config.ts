import { config } from 'dotenv'

import { Env, parseEnv } from '@truesparrow/common-js'
import { getFromEnv } from '@truesparrow/common-server-js'
import { Auth0ServerConfig } from '@truesparrow/identity-sdk-js'


config({ path: 'config/env.identity' });

export const ENV: Env = parseEnv(getFromEnv('ENV'));

export const NAME: string = 'identity';
export const HOST: string = getFromEnv('HOST');
export const PORT: number = parseInt(getFromEnv('PORT'), 10);
export const ORIGIN: string = `http://${HOST}:${PORT}`;

export const POSTGRES_HOST: string = getFromEnv('POSTGRES_HOST');
export const POSTGRES_PORT: number = parseInt(getFromEnv('POSTGRES_PORT'), 10);
export const POSTGRES_DATABASE: string = getFromEnv('POSTGRES_DATABASE');
export const POSTGRES_USERNAME: string = getFromEnv('POSTGRES_USERNAME');
export const POSTGRES_PASSWORD: string = getFromEnv('POSTGRES_PASSWORD');
export const POSTGRES_MIGRATIONS_DIR: string = getFromEnv('POSTGRES_MIGRATIONS_DIR');
export const POSTGRES_MIGRATIONS_TABLE: string = getFromEnv('POSTGRES_MIGRATIONS_TABLE');

export const AUTH0_SERVER_CONFIG: Auth0ServerConfig = {
    clientId: getFromEnv('AUTH0_CLIENT_ID'),
    clientSecret: getFromEnv('AUTH0_CLIENT_SECRET'),
    domain: getFromEnv('AUTH0_DOMAIN'),
    loginCallbackUri: '', // Not used here
    styleLogoUri: '', // Not used here
    stylePrimaryColor: '', // Not used here
    styleApplicationName: '' // Not used here
};
export const AUTH0_CACHE_TTL_IN_SECS: number = 10 * 60; // 10 minutes
