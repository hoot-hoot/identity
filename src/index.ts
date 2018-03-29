import * as auth0 from 'auth0'
import * as express from 'express'
import * as knex from 'knex'
import 'log-timestamp'
import * as NodeCache from 'node-cache'

import { isForDevelopment } from '@truesparrow/common-js'
import { newHealthCheckRouter } from '@truesparrow/common-server-js'

import * as config from './config'
import { newIdentityRouter } from './identity-router'
import { Repository } from './repository'
import { newTestRouter } from './test-router'


async function main() {
    const auth0Client = new auth0.AuthenticationClient({
        clientId: config.AUTH0_SERVER_CONFIG.clientId,
        domain: config.AUTH0_SERVER_CONFIG.domain
    });
    const auth0Cache = new NodeCache({
        stdTTL: config.AUTH0_CACHE_TTL_IN_SECS,
        useClones: false
    });
    const conn = knex({
        client: 'pg',
        connection: {
            host: config.POSTGRES_HOST,
            port: config.POSTGRES_PORT,
            database: config.POSTGRES_DATABASE,
            user: config.POSTGRES_USERNAME,
            password: config.POSTGRES_PASSWORD
        }
    });
    const appConfig = {
        env: config.ENV,
        name: config.NAME,
        forceDisableLogging: false,
        logglyToken: null,
        logglySubdomain: null,
        rollbarToken: null
    };
    const repository = new Repository(conn);
    const identityRouter = newIdentityRouter(appConfig, auth0Client, auth0Cache, repository);
    const healthCheckRouter = newHealthCheckRouter();
    const testRouter = newTestRouter(appConfig, auth0Cache, repository);

    console.log('Starting up');

    console.log('Initializing repository & performing migrations');
    await repository.init();

    console.log('Starting web server');

    const app = express();
    app.disable('x-powered-by');
    app.use('/api', identityRouter);
    app.use('/status', healthCheckRouter);
    if (isForDevelopment(config.ENV)) {
        app.use('/test', testRouter);
    }

    app.listen(config.PORT, '0.0.0.0', () => {
        console.log(`Started ${config.NAME} service on ${config.PORT}`);
    });
}


main();
