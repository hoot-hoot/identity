import * as auth0 from 'auth0'
import * as express from 'express'
import * as knex from 'knex'
import 'log-timestamp'
import * as NodeCache from 'node-cache'

import { isForDevelopment } from '@truesparrow/common-js'

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
        connection: config.DATABASE_URL
    });
    const appConfig = {
        env: config.ENV,
        name: config.NAME,
        clients: config.CLIENTS,
        forceDisableLogging: false,
        logglyToken: config.LOGGLY_TOKEN,
        logglySubdomain: config.LOGGLY_SUBDOMAIN,
        rollbarToken: config.ROLLBAR_TOKEN
    };
    const repository = new Repository(conn);
    const identityRouter = newIdentityRouter(appConfig, auth0Client, auth0Cache, repository);
    const testRouter = newTestRouter(appConfig, repository);

    console.log('Starting up');

    console.log('Initializing repository & performing migrations');
    await repository.init();

    console.log('Starting web server');

    const app = express();
    app.disable('x-powered-by');
    app.use('/api', identityRouter);
    if (isForDevelopment(config.ENV)) {
        app.use('/test', testRouter);
    }
    app.listen(config.PORT, config.ADDRESS, () => {
        console.log(`Started ${config.NAME} service on ${config.ADDRESS}:${config.PORT}`);
    });
}


main();
