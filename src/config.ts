import { config } from 'dotenv'

import { Env, parseEnv } from '@truesparrow/common-js'
import { getFromEnv } from '@truesparrow/common-server-js'
import { Auth0ServerConfig } from '@truesparrow/identity-sdk-js'


config();

// Common to all services

export const ENV: Env = parseEnv(getFromEnv('COMMON_ENV'));

// Specific to identity service

export const NAME: string = 'identity';
export const HOST: string = getFromEnv('IDENTITY_SERVICE_HOST');
export const PORT: number = parseInt(getFromEnv('IDENTITY_SERVICE_PORT'), 10);
export const ORIGIN: string = `http://${HOST}:${PORT}`;

const databaseHost = getFromEnv('POSTGRES_HOST');
const databasePort = getFromEnv('POSTGRES_PORT');
const databaseDatabase = getFromEnv('POSTGRES_DATABASE');
const databaseUserName = getFromEnv('IDENTITY_DATABASE_USERNAME');
const databasePassword = getFromEnv('IDENTITY_DATABASE_PASSWORD');

export const DATABASE_URL: string = `postgresql://${databaseUserName}:${databasePassword}@${databaseHost}:${databasePort}/${databaseDatabase}`;
export const DATABASE_MIGRATIONS_DIR: string = getFromEnv('IDENTITY_DATABASE_MIGRATIONS_DIR');
export const DATABASE_MIGRATIONS_TABLE: string = getFromEnv('IDENTITY_DATABASE_MIGRATIONS_TABLE');

export const AUTH0_SERVER_CONFIG: Auth0ServerConfig = {
    clientId: getFromEnv('IDENTITY_AUTH0_CLIENT_ID'),
    clientSecret: getFromEnv('IDENTITY_AUTH0_CLIENT_SECRET'),
    domain: getFromEnv('IDENTITY_AUTH0_DOMAIN'),
    loginCallbackUri: '' // Not used here
};
export const AUTH0_CACHE_TTL_IN_SECS: number = 10 * 60; // 10 minutes
