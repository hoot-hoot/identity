/** Defines the IdentityRouter. */

/** Imports. Also so typedoc works correctly. */
import * as auth0 from 'auth0'
import { wrap } from 'async-middleware'
import * as cookieParser from 'cookie-parser'
import * as compression from 'compression'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import * as NodeCache from 'node-cache'
import { ArrayOf, MarshalFrom } from 'raynor'
import * as r from 'raynor'

import { isNotOnServer } from '@truesparrow/common-js'
import {
    newCommonApiServerMiddleware,
    // newCommonServerMiddleware,
    newLocalCommonServerMiddleware,
    Request
} from '@truesparrow/common-server-js'
import {
    SessionAndTokenResponse,
    SessionResponse,
    UsersInfoResponse
} from '@truesparrow/identity-sdk-js/dtos'

import { AppConfig } from './app-config'
import { Auth0Profile } from './auth0-profile'
import { Repository } from './repository'
import { extractSessionToken, extractXsrfToken } from './utils'


/**
 * Construct an IdentityRouter. This is an full formed and independent {@link express.Router}
 * which implements the HTTP API for the identity service. It makes the connection between clients,
 * external services and the business logic encapsulated in the {@link Repository}.
 * @note The router has the following paths exposed:
 *    @path /sessions POST, GET, DELETE
 *    @path /sessions/agree-to-cookie-policy POST
 *    @path /users POST, GET
 *    @path /users-info?ids GET
 * @param config - the application configuration.
 * @param auth0Client - a client for Auth0.
 * @param auth0Cache - a cache which sits in front of Auth0.
 * @param repository - a repository.
 * @return A {@link express.Router} doing all of the above.
 */
export function newIdentityRouter(
    config: AppConfig,
    auth0Client: auth0.AuthenticationClient,
    auth0Cache: NodeCache,
    repository: Repository): express.Router {
    const auth0ProfileMarshaller = new (MarshalFrom(Auth0Profile))();
    const sessionAndTokenResponseMarshaller = new (MarshalFrom(SessionAndTokenResponse))();
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();
    const usersInfoResponseMarshaller = new (MarshalFrom(UsersInfoResponse))();
    const idsMarshaller = new (ArrayOf(r.IdMarshaller))();

    const identityRouter = express.Router();

    identityRouter.use(cookieParser());
    if (true || isNotOnServer(config.env)) {
        identityRouter.use(newLocalCommonServerMiddleware(config.name, config.env, config.forceDisableLogging));
    } else {
        // identityRouter.use(newCommonServerMiddleware(
        //     config.name,
        //     config.env,
        //     config.logglyToken as string,
        //     config.logglySubdomain as string,
        //     config.rollbarToken as string));
    }
    identityRouter.use(compression({ threshold: 0 }));
    identityRouter.use(newCommonApiServerMiddleware());

    identityRouter.post('/sessions', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);

        try {
            const [sessionToken, session, created] = await repository.getOrCreateSession(currentSessionToken, req.requestTime);

            const sessionAndTokenResponse = new SessionAndTokenResponse();
            sessionAndTokenResponse.sessionToken = sessionToken;
            sessionAndTokenResponse.session = session;

            res.status(created ? HttpStatus.CREATED : HttpStatus.OK);
            res.write(JSON.stringify(sessionAndTokenResponseMarshaller.pack(sessionAndTokenResponse)));
            res.end();
        } catch (e) {
            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.get('/sessions', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        try {
            const session = await repository.getSession(currentSessionToken);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = session;

            res.write(JSON.stringify(sessionResponseMarshaller.pack(sessionResponse)));
            res.status(HttpStatus.OK);
            res.end();
        } catch (e) {
            if (e.name == 'SessionNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.delete('/sessions', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        const xsrfToken = extractXsrfToken(req);
        if (xsrfToken == null) {
            req.log.warn('Expected a XSRF token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        try {
            await repository.removeSession(currentSessionToken, req.requestTime, xsrfToken);

            res.status(HttpStatus.NO_CONTENT);
            res.end();
        } catch (e) {
            if (e.name == 'SessionNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            if (e.name == 'XsrfTokenMismatchError') {
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.post('/sessions/agree-to-cookie-policy', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        const xsrfToken = extractXsrfToken(req);
        if (xsrfToken == null) {
            req.log.warn('Expected a XSRF token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        try {
            const session = await repository.agreeToCookiePolicyForSession(currentSessionToken, req.requestTime, xsrfToken);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = session;

            res.status(HttpStatus.OK);
            res.write(JSON.stringify(sessionResponseMarshaller.pack(sessionResponse)));
            res.end();
        } catch (e) {

            if (e.name == 'SessionNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            if (e.name == 'UserNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            if (e.name == 'XsrfTokenMismatchError') {
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.post('/users', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        const xsrfToken = extractXsrfToken(req);
        if (xsrfToken == null) {
            req.log.warn('Expected a XSRF token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        let auth0Profile: Auth0Profile | undefined = undefined;
        try {
            const auth0AccessToken = currentSessionToken.userToken as string;
            auth0Profile = auth0Cache.get(auth0AccessToken);

            if (auth0Profile == undefined) {
                const auth0ProfileSerialized = await auth0Client.getProfile(auth0AccessToken);

                if (auth0ProfileSerialized == 'Unauthorized') {
                    req.log.warn('Token was not accepted by Auth0');
                    res.status(HttpStatus.UNAUTHORIZED);
                    res.end();
                    return;
                }

                auth0Profile = auth0ProfileMarshaller.extract(auth0ProfileSerialized);
                auth0Cache.set(auth0AccessToken, auth0Profile);
            }
        } catch (e) {
            req.log.error(e, 'Auth0 Error');
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
            return;
        }

        try {
            const [sessionToken, session, created] = await repository.getOrCreateUserOnSession(currentSessionToken, auth0Profile, req.requestTime, xsrfToken);

            const sessionTokenAndSessionResponse = new SessionAndTokenResponse();
            sessionTokenAndSessionResponse.sessionToken = sessionToken;
            sessionTokenAndSessionResponse.session = session;

            res.status(created ? HttpStatus.CREATED : HttpStatus.OK);
            res.write(JSON.stringify(sessionAndTokenResponseMarshaller.pack(sessionTokenAndSessionResponse)));
            res.end();
        } catch (e) {
            if (e.name == 'SessionNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            if (e.name == 'XsrfTokenMismatchError') {
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.get('/users', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        let auth0Profile: Auth0Profile | undefined = undefined;
        try {
            const auth0AccessToken = currentSessionToken.userToken as string;
            auth0Profile = auth0Cache.get(auth0AccessToken);

            if (auth0Profile == undefined) {
                const auth0ProfileSerialized = await auth0Client.getProfile(auth0AccessToken);

                if (auth0ProfileSerialized == 'Unauthorized') {
                    req.log.warn('Token was not accepted by Auth0');
                    res.status(HttpStatus.UNAUTHORIZED);
                    res.end();
                    return;
                }

                auth0Profile = auth0ProfileMarshaller.extract(auth0ProfileSerialized);
                auth0Cache.set(auth0AccessToken, auth0Profile);
            }
        } catch (e) {
            req.log.error(e, 'Auth0 Error');
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
            return;
        }

        try {
            const session = await repository.getUserOnSession(currentSessionToken, auth0Profile);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = session;

            res.status(HttpStatus.OK);
            res.write(JSON.stringify(sessionResponseMarshaller.pack(sessionResponse)));
            res.end();
        } catch (e) {
            if (e.name == 'UserNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            if (e.name == 'SessionNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    identityRouter.get('/users-info', wrap(async (req: Request, res: express.Response) => {
        const currentSessionToken = extractSessionToken(req);
        if (currentSessionToken == null) {
            req.log.warn('Expected a session token to exist');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        if (req.query.ids === undefined) {
            req.log.warn('Missing required "ids" parameter');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        let ids: number[] | null = null;
        try {
            ids = idsMarshaller.extract(JSON.parse(decodeURIComponent(req.query.ids)));
        } catch (e) {
            req.log.warn('Could not decode "ids" parameter');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        if (ids.length == 0) {
            req.log.warn('Need to return some ids');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        if (ids.length > Repository.MAX_NUMBER_OF_USERS_TO_RETURN) {
            req.log.warn(`Can't retrieve ${ids.length} users`);
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        try {
            const usersInfo = await repository.getUsersInfo(ids);
            const usersInfoResponse = new UsersInfoResponse();
            usersInfoResponse.usersInfo = usersInfo;

            res.write(JSON.stringify(usersInfoResponseMarshaller.pack(usersInfoResponse)));
            res.status(HttpStatus.OK);
            res.end();
        } catch (e) {
            if (e.name == 'UserNotFoundError') {
                res.status(HttpStatus.NOT_FOUND);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
        }
    }));

    return identityRouter;
}
