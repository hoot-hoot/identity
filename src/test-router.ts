/** Defines the TestRouter. */

/** Imports. Also so typedoc works correctly. */
import { wrap } from 'async-middleware'
import * as compression from 'compression'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import * as NodeCache from 'node-cache'
import { MarshalFrom } from 'raynor'

import {
    newCommonApiServerMiddleware,
    newLocalCommonServerMiddleware,
    Request
} from '@truesparrow/common-server-js'
import {
    SessionAndTokenResponse
} from '@truesparrow/identity-sdk-js/dtos'

import { AppConfig } from './app-config'
import { Repository } from './repository'
import { extractSessionToken } from './utils'
import { Auth0Profile } from './auth0-profile';


/**
 * Construct a TestRouter. This is a fully formed and independent {@link express.Router}
 * which implements a bunch of test-only code for the identity service. The aim is to easily be able
 * to do some high-level operations, such as clearing out test data, or creating fake users etc.
 * @note The router has the following paths exposed:
 *     @path /clear-out POST
 *     @path /create-test-user POST
 * @note For all users methods in here create or work with, the auth0Cache is modified and updated
 *    with correct information. This ensures Auth0 won't ever be hit during any other API call.
 * @param config - the application configuration.
 * @param auth0Cache - a cache which sits in front of Auth0.
 * @param repository - a repository.
 * @return A {link express.Router} doing the above.
 */
export function newTestRouter(config: AppConfig, auth0Cache: NodeCache, repository: Repository): express.Router {
    const auth0ProfileMarshaller = new (MarshalFrom(Auth0Profile))();
    const sessionAndTokenResponseMarshaller = new (MarshalFrom(SessionAndTokenResponse))();

    const testRouter = express.Router();

    testRouter.use(newLocalCommonServerMiddleware(config.name, config.env, config.forceDisableLogging));
    testRouter.use(compression({ threshold: 0 }));
    testRouter.use(newCommonApiServerMiddleware(config.clients));

    testRouter.post('/clear-out', wrap(async (req: Request, res: express.Response) => {
        try {
            await repository.testClearOut();

            res.status(HttpStatus.OK);
            res.end();
        } catch (e) {
            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    testRouter.post('/create-test-user', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        let auth0Profile: Auth0Profile | null = null;
        try {
            auth0Profile = auth0ProfileMarshaller.extract(req.body);
        } catch (e) {
            console.log(e);
            req.log.warn('Could not decode auth0 profile');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        try {
            const [sessionToken, session, created] = await repository.testCreateUser(currentSessionToken, auth0Profile, req.requestTime);
            auth0Cache.set(currentSessionToken.userToken as string, auth0Profile);

            const sessionTokenAndSessionResponse = new SessionAndTokenResponse();
            sessionTokenAndSessionResponse.sessionToken = sessionToken;
            sessionTokenAndSessionResponse.session = session;

            res.status(created ? HttpStatus.CREATED : HttpStatus.OK);
            res.write(JSON.stringify(sessionAndTokenResponseMarshaller.pack(sessionTokenAndSessionResponse)));
            res.end();
        } catch (e) {
            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    return testRouter;
}
