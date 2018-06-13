import * as auth0 from 'auth0'
import { expect } from 'chai'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import 'mocha'
import * as NodeCache from 'node-cache'
import { MarshalFrom } from 'raynor'
import * as td from 'testdouble'
import { agent, Test } from 'supertest'
import * as uuid from 'uuid'

import { Env } from '@truesparrow/common-js'
import {
    SESSION_TOKEN_HEADER_NAME,
    XSRF_TOKEN_HEADER_NAME
} from '@truesparrow/identity-sdk-js/client'
import { SessionAndTokenResponse, SessionResponse, UsersInfoResponse } from '@truesparrow/identity-sdk-js/dtos'
import { PrivateUser, PublicUser, Role, Session, SessionState, UserState } from '@truesparrow/identity-sdk-js/entities'
import { SessionToken } from '@truesparrow/identity-sdk-js/session-token'

import { AppConfig } from './app-config'
import { Auth0Profile } from './auth0-profile'
import { newIdentityRouter } from './identity-router'
import {
    Repository,
    SessionNotFoundError,
    UserNotFoundError,
    XsrfTokenMismatchError
} from './repository'


describe('IdentityRouter', () => {
    const localAppConfig: AppConfig = {
        env: Env.Local,
        name: 'identity',
        forceDisableLogging: true,
        logglyToken: null,
        logglySubdomain: null,
        rollbarToken: null
    };

    const stagingAppConfig: AppConfig = {
        env: Env.Staging,
        name: 'identity',
        forceDisableLogging: true,
        logglyToken: 'A FAKE TOKEN',
        logglySubdomain: 'a-fake-subdomain',
        rollbarToken: null
    };

    const rightNow: Date = new Date(Date.now());

    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
    const sessionAndTokenResponseMarshaller = new (MarshalFrom(SessionAndTokenResponse))();
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();
    const usersInfoResponseMarshaller = new (MarshalFrom(UsersInfoResponse))();
    const auth0ProfileMarshaller = new (MarshalFrom(Auth0Profile))();

    const theSessionToken = new SessionToken(uuid());

    const theSession = new Session();
    theSession.state = SessionState.Active;
    theSession.xsrfToken = ('0' as any).repeat(64);
    theSession.agreedToCookiePolicy = false;
    theSession.timeCreated = rightNow;
    theSession.timeLastUpdated = rightNow;

    const theSessionWithAgreement = new Session();
    theSessionWithAgreement.state = SessionState.Active;
    theSessionWithAgreement.xsrfToken = ('0' as any).repeat(64);
    theSessionWithAgreement.agreedToCookiePolicy = true;
    theSessionWithAgreement.timeCreated = rightNow;
    theSessionWithAgreement.timeLastUpdated = rightNow;

    const theSessionTokenWithUser = new SessionToken(uuid(), 'x0bjohntok');

    const theSessionWithUser = new Session();
    theSessionWithUser.state = SessionState.ActiveAndLinkedWithUser;
    theSessionWithUser.xsrfToken = ('0' as any).repeat(64);
    theSessionWithUser.agreedToCookiePolicy = false;
    theSessionWithUser.timeCreated = rightNow;
    theSessionWithUser.timeLastUpdated = rightNow;
    theSessionWithUser.user = new PrivateUser();
    theSessionWithUser.user.id = 1;
    theSessionWithUser.user.state = UserState.Active;
    theSessionWithUser.user.role = Role.Regular;
    theSessionWithUser.user.name = 'John Doe';
    theSessionWithUser.user.firstName = 'John';
    theSessionWithUser.user.lastName = 'Doe';
    theSessionWithUser.user.emailAddress = 'john.doe@example.com';
    theSessionWithUser.user.pictureUri = 'https://example.com/picture.jpg';
    theSessionWithUser.user.language = 'en';
    theSessionWithUser.user.timeCreated = rightNow;
    theSessionWithUser.user.timeLastUpdated = rightNow;
    theSessionWithUser.user.agreedToCookiePolicy = false;
    theSessionWithUser.user.userIdHash = ('f' as any).repeat(64);

    const auth0ProfileJohnDoe: Auth0Profile = new Auth0Profile();
    auth0ProfileJohnDoe.name = 'John Doe';
    auth0ProfileJohnDoe.firstName = 'John';
    auth0ProfileJohnDoe.lastName = 'Doe';
    auth0ProfileJohnDoe.emailAddress = 'john.doe@example.com';
    auth0ProfileJohnDoe.picture = 'https://example.com/picture.jpg';
    auth0ProfileJohnDoe.userId = 'x0bjohn';
    auth0ProfileJohnDoe.language = 'en';

    const userInfoJohnDoe = new PublicUser();
    userInfoJohnDoe.id = 1;
    userInfoJohnDoe.state = UserState.Active;
    userInfoJohnDoe.role = Role.Regular;
    userInfoJohnDoe.name = 'John Doe';
    userInfoJohnDoe.firstName = 'John';
    userInfoJohnDoe.lastName = 'Doe';
    userInfoJohnDoe.emailAddress = 'john.doe@example.com';
    userInfoJohnDoe.pictureUri = 'https://example.com/picture1.jpg';
    userInfoJohnDoe.language = 'en';
    userInfoJohnDoe.timeCreated = rightNow;
    userInfoJohnDoe.timeLastUpdated = rightNow;

    const userInfoJaneDoe = new PublicUser();
    userInfoJaneDoe.id = 2;
    userInfoJaneDoe.state = UserState.Active;
    userInfoJaneDoe.role = Role.Regular;
    userInfoJaneDoe.name = 'Jane Doe';
    userInfoJaneDoe.firstName = 'Jane';
    userInfoJaneDoe.lastName = 'Doe';
    userInfoJaneDoe.emailAddress = 'jane.doe@example.com';
    userInfoJaneDoe.pictureUri = 'https://example.com/picture2.jpg';
    userInfoJaneDoe.language = 'en';
    userInfoJaneDoe.timeCreated = rightNow;
    userInfoJaneDoe.timeLastUpdated = rightNow;

    const auth0Client = td.object({
        getProfile: (_t: string) => { }
    });

    const auth0Cache = td.object({
        get: (_k: string) => { },
        set: (_k: string, _v: any) => { }
    });

    const repository = td.object({
        getOrCreateSession: (_t: SessionToken | null, _c: Date) => { },
        getSession: (_t: SessionToken) => { },
        removeSession: (_t: SessionToken, _d: Date, _x: string) => { },
        agreeToCookiePolicyForSession: (_t: SessionToken, _d: Date, _x: string) => { },
        getOrCreateUserOnSession: (_t: SessionToken, _a: Auth0Profile, _d: Date, _x: string) => { },
        getUserOnSession: (_t: SessionToken, _a: Auth0Profile) => { },
        getUsersInfo: (_ids: number[]) => { }
    });

    afterEach('reset test doubles', () => {
        td.reset();
    });

    it('can be constructed', () => {
        const identityRouter = newIdentityRouter(localAppConfig, auth0Client as auth0.AuthenticationClient, auth0Cache as NodeCache, repository as Repository);

        expect(identityRouter).is.not.null;
    });

    it('can be constructed with live settings', () => {
        const identityRouter = newIdentityRouter(stagingAppConfig, auth0Client as auth0.AuthenticationClient, auth0Cache as NodeCache, repository as Repository);

        expect(identityRouter).is.not.null;
    });

    describe('/sessions POST', () => {
        it('should return the newly created session when there is no session information', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.getOrCreateSession(null, td.matchers.isA(Date))).thenReturn([theSessionToken, theSession, true]);

            await appAgent
                .post('/sessions')
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect(HttpStatus.CREATED)
                .then(response => {
                    const result = sessionAndTokenResponseMarshaller.extract(response.body);
                    expect(result.sessionToken).to.eql(theSessionToken);
                    expect(result.session).to.eql(theSession);
                });
        });

        it('should return a newly created session with bad session information', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.getOrCreateSession(null, td.matchers.isA(Date))).thenReturn([theSessionToken, theSession, true]);

            await appAgent
                .post('/sessions')
                .set(SESSION_TOKEN_HEADER_NAME, 'bad data here')
                .expect(HttpStatus.CREATED)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionAndTokenResponseMarshaller.extract(response.body);
                    expect(result.sessionToken).to.eql(theSessionToken);
                    expect(result.session).to.eql(theSession);
                });
        });

        it('should return an already existing session', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.getOrCreateSession(theSessionToken, td.matchers.isA(Date))).thenReturn([theSessionToken, theSession, false]);

            await appAgent
                .post('/sessions')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionAndTokenResponseMarshaller.extract(response.body);
                    expect(result.sessionToken).to.eql(theSessionToken);
                    expect(result.session).to.eql(theSession);
                });
        });

        badRepository('/sessions', 'post', { getOrCreateSession: (_t: SessionToken | null, _c: Date) => { } }, new Map<string, [Error, number]>([
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occured'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/sessions GET', () => {
        it('should return an existing session', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.getSession(theSessionToken)).thenReturn(theSession);

            await appAgent
                .get('/sessions')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionResponseMarshaller.extract(response.body);
                    expect(result.session).to.eql(theSession);
                });
        });

        badSessionToken('/sessions', 'get');
        badRepository('/sessions', 'get', { getSession: (_t: SessionToken) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the session is not present', [new SessionNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/sessions DELETE', () => {
        it('should succeed', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.removeSession(theSessionToken, td.matchers.isA(Date), theSession.xsrfToken)).thenReturn();

            await appAgent
                .delete('/sessions')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .set(XSRF_TOKEN_HEADER_NAME, theSession.xsrfToken)
                .expect(HttpStatus.NO_CONTENT)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(5);

                    expect(response.text).to.have.length(0);
                });
        });

        badSessionToken('/sessions', 'delete');
        badXsrfToken('/sessions', 'delete');
        badRepository('/sessions', 'delete', { removeSession: (_t: SessionToken, _d: Date, _x: string) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the session is not present', [new SessionNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['BAD_REQUEST when the XSRF token is mismatched', [new XsrfTokenMismatchError('Invalid token'), HttpStatus.BAD_REQUEST]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/sessions/agree-to-cookie-policy POST', () => {
        it('should succeed', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.agreeToCookiePolicyForSession(theSessionToken, td.matchers.isA(Date), theSession.xsrfToken)).thenReturn(theSessionWithAgreement);

            await appAgent
                .post('/sessions/agree-to-cookie-policy')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .set(XSRF_TOKEN_HEADER_NAME, theSession.xsrfToken)
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionResponseMarshaller.extract(response.body);
                    expect(result.session).to.eql(theSessionWithAgreement);
                });
        });

        badSessionToken('/sessions/agree-to-cookie-policy', 'post');
        badXsrfToken('/sessions/agree-to-cookie-policy', 'post');
        badRepository('/sessions/agree-to-cookie-policy', 'post', { agreeToCookiePolicyForSession: (_t: SessionToken, _d: Date, _x: string) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the session is not present', [new SessionNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['NOT_FOUND when the user is not present', [new UserNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['BAD_REQUEST when the XSRF token is mismatched', [new XsrfTokenMismatchError('Invalid token'), HttpStatus.BAD_REQUEST]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/users POST', () => {
        it('should return a new user when there isn\'t one', async () => {
            const appAgent = buildAppAgent();

            td.when(auth0Client.getProfile(theSessionTokenWithUser.userToken as string))
                .thenReturn(auth0ProfileMarshaller.pack(auth0ProfileJohnDoe));
            td.when(repository.getOrCreateUserOnSession(theSessionTokenWithUser, auth0ProfileJohnDoe, td.matchers.isA(Date), theSessionWithUser.xsrfToken))
                .thenReturn([theSessionTokenWithUser, theSessionWithUser, true]);

            await appAgent
                .post('/users')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                .set(XSRF_TOKEN_HEADER_NAME, theSessionWithUser.xsrfToken)
                .expect(HttpStatus.CREATED)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionAndTokenResponseMarshaller.extract(response.body);
                    expect(result.sessionToken).to.eql(theSessionTokenWithUser);
                    expect(result.session).to.eql(theSessionWithUser);
                });
        });

        it('should return an existing user when there is one', async () => {
            const appAgent = buildAppAgent();

            td.when(auth0Client.getProfile(theSessionTokenWithUser.userToken as string))
                .thenReturn(auth0ProfileMarshaller.pack(auth0ProfileJohnDoe));
            td.when(repository.getOrCreateUserOnSession(theSessionTokenWithUser, auth0ProfileJohnDoe, td.matchers.isA(Date), theSessionWithUser.xsrfToken))
                .thenReturn([theSessionTokenWithUser, theSessionWithUser, false]);

            await appAgent
                .post('/users')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                .set(XSRF_TOKEN_HEADER_NAME, theSessionWithUser.xsrfToken)
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionAndTokenResponseMarshaller.extract(response.body);
                    expect(result.sessionToken).to.eql(theSessionTokenWithUser);
                    expect(result.session).to.eql(theSessionWithUser);
                });
        });

        badSessionToken('/users', 'post');
        badXsrfToken('/users', 'post');
        badAuth0('/users', 'post', new Map<string, [string, number]>([
            ['UNAUTHORIZED when the token was not accepted', ['Unauthorized', HttpStatus.UNAUTHORIZED]],
            ['INTERNAL_SERVER_ERROR when the result could not be parsed', ['A bad response', HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
        badRepository('/users', 'post', { getOrCreateUserOnSession: (_t: SessionToken, _a: Auth0Profile, _d: Date, _x: string) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the session is not present', [new SessionNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['BAD_REQUEST when the XSRF token is mismatched', [new XsrfTokenMismatchError('Invalid token'), HttpStatus.BAD_REQUEST]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/users GET', () => {
        it('should return an existing user', async () => {
            const appAgent = buildAppAgent();

            td.when(auth0Client.getProfile(theSessionTokenWithUser.userToken as string))
                .thenReturn(auth0ProfileMarshaller.pack(auth0ProfileJohnDoe));
            td.when(repository.getUserOnSession(theSessionTokenWithUser, auth0ProfileJohnDoe))
                .thenReturn(theSessionWithUser);

            await appAgent
                .get('/users')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = sessionResponseMarshaller.extract(response.body);
                    expect(result.session).to.eql(theSessionWithUser);
                });
        });

        badSessionToken('/users', 'get');
        badAuth0('/users', 'get', new Map<string, [string, number]>([
            ['UNAUTHORIZED when the token was not accepted', ['Unauthorized', HttpStatus.UNAUTHORIZED]],
            ['INTERNAL_SERVER_ERROR when the result could not be parsed', ['A bad response', HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
        badRepository('/users', 'get', { getUserOnSession: (_t: SessionToken, _a: Auth0Profile, _d: Date, _x: string) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the session is not present', [new SessionNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['NOT_FOUND when the user is not present', [new UserNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    describe('/users-info GET', () => {
        it('should retrieve requested users', async () => {
            const appAgent = buildAppAgent();

            td.when(repository.getUsersInfo([1, 2])).thenReturn([userInfoJohnDoe, userInfoJaneDoe]);

            await appAgent
                .get('/users-info?ids=%5B1%2C2%5D') // ids=[1,2]
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                .expect(HttpStatus.OK)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    const result = usersInfoResponseMarshaller.extract(response.body);
                    expect(result.usersInfo).to.eql([userInfoJohnDoe, userInfoJaneDoe]);
                });
        });

        it('should return BAD_REQUEST when there are no ids', async () => {
            const appAgent = buildAppAgent();

            await appAgent
                .get('/users-info')
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                .expect(HttpStatus.BAD_REQUEST)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    expect(response.text).to.have.length(0);
                });
        });

        for (let badIds of [
            '',
            'bad-bad',
            '%5B%5D',
            '%5B1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%5D']) {
            it(`should return BAD_REQUEST when the bad ids are "${badIds}"`, async () => {
                const appAgent = buildAppAgent();

                await appAgent
                    .get(`/users-info?ids=${badIds}`)
                    .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                    .expect(HttpStatus.BAD_REQUEST)
                    .expect('Content-Type', 'application/json; charset=utf-8')
                    .expect('Transfer-Encoding', 'chunked')
                    .expect('Content-Encoding', 'gzip')
                    .expect('Vary', 'Accept-Encoding')
                    .expect('Connection', 'close')
                    .then(response => {
                        expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                        expect(Object.keys(response.header)).has.length(6);

                        expect(response.text).to.have.length(0);
                    });
            });
        }

        badSessionToken('/users-info?ids=%5B1%2C2%5D', 'get');
        badRepository('/users-info?ids=%5B1%2C2%5D', 'get', { getUsersInfo: (_ids: number[]) => { } }, new Map<string, [Error, number]>([
            ['NOT_FOUND when the user is not present', [new UserNotFoundError('Not found'), HttpStatus.NOT_FOUND]],
            ['INTERNAL_SERVER_ERROR when the repository errors', [new Error('An error occurred'), HttpStatus.INTERNAL_SERVER_ERROR]]
        ]));
    });

    function buildAppAgent() {
        const router = newIdentityRouter(localAppConfig, auth0Client as auth0.AuthenticationClient, auth0Cache as NodeCache, repository as Repository);
        const app = express();
        app.disable('x-powered-by');
        app.use('/', router);

        return agent(app);
    }

    type Method = 'post' | 'get' | 'delete';

    function newAgent(uri: string, method: Method): Test {
        const appAgent = buildAppAgent();

        switch (method) {
            case 'post':
                return appAgent.post(uri);
            case 'get':
                return appAgent.get(uri);
            case 'delete':
                return appAgent.delete(uri);
        }
    }

    function badSessionToken(uri: string, method: Method) {
        it('should return BAD_REQUEST when there is no session token', async () => {
            const restOfTest = newAgent(uri, method);

            await restOfTest
                .set('Origin', 'core')
                .expect(HttpStatus.BAD_REQUEST)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    expect(response.text).has.length(0);
                });
        });

        it('should return BAD_REQUEST when the session token is bad', async () => {
            const restOfTest = newAgent(uri, method);

            await restOfTest
                .set(SESSION_TOKEN_HEADER_NAME, 'bad token')
                .set('Origin', 'core')
                .expect(HttpStatus.BAD_REQUEST)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    expect(response.text).has.length(0);
                });
        });
    }

    function badXsrfToken(uri: string, method: Method) {
        it('should return BAD_REQUEST when the xsrf token is missing', async () => {
            const restOfTest = newAgent(uri, method);

            await restOfTest
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .set('Origin', 'core')
                .expect(HttpStatus.BAD_REQUEST)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    expect(response.text).has.length(0);
                });
        });

        it('should return BAD_REQUEST when the xsrf token is invalid', async () => {
            const restOfTest = newAgent(uri, method);

            await restOfTest
                .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                .set(XSRF_TOKEN_HEADER_NAME, 'A BAD TOKEN')
                .set('Origin', 'core')
                .expect(HttpStatus.BAD_REQUEST)
                .expect('Content-Type', 'application/json; charset=utf-8')
                .expect('Transfer-Encoding', 'chunked')
                .expect('Content-Encoding', 'gzip')
                .expect('Vary', 'Accept-Encoding')
                .expect('Connection', 'close')
                .then(response => {
                    expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                    expect(Object.keys(response.header)).has.length(6);

                    expect(response.text).has.length(0);
                });
        })
    }

    function badAuth0(uri: string, method: Method, cases: Map<string, [string, number]>) {
        for (let [oneCase, [getProfileResult, statusCode]] of cases) {
            it(`should return ${oneCase}`, async () => {
                const restOfTest = newAgent(uri, method);

                td.when(auth0Client.getProfile(theSessionTokenWithUser.userToken as string))
                    .thenReturn(getProfileResult);

                await restOfTest
                    .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))
                    .set(XSRF_TOKEN_HEADER_NAME, theSessionWithUser.xsrfToken)
                    .set('Origin', 'core')
                    .expect(statusCode)
                    .expect('Content-Type', 'application/json; charset=utf-8')
                    .expect('Transfer-Encoding', 'chunked')
                    .expect('Content-Encoding', 'gzip')
                    .expect('Vary', 'Accept-Encoding')
                    .expect('Connection', 'close')
                    .then(response => {
                        expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                        expect(Object.keys(response.header)).has.length(6);

                        expect(response.text).to.have.length(0);
                    });
            });
        }
    }

    function badRepository(uri: string, method: Method, repositoryTemplate: object, cases: Map<string, [Error, number]>) {
        for (let [oneCase, [error, statusCode]] of cases) {
            const methodName = Object.keys(repositoryTemplate)[0]
            it(`should return ${oneCase}`, async () => {
                const repository = td.object(repositoryTemplate);

                const router = newIdentityRouter(localAppConfig, auth0Client as auth0.AuthenticationClient, auth0Cache as NodeCache, repository as Repository);
                const app = express();
                app.disable('x-powered-by');
                app.use('/', router);

                const appAgent = agent(app);
                let restOfTest: Test | null = null;

                switch (method) {
                    case 'post':
                        restOfTest = appAgent.post(uri);
                        break;
                    case 'get':
                        restOfTest = appAgent.get(uri);
                        break;
                    case 'delete':
                        restOfTest = appAgent.delete(uri);
                        break;
                }

                td.when(auth0Client.getProfile(td.matchers.anything()))
                    .thenReturn(auth0ProfileMarshaller.pack(auth0ProfileJohnDoe));
                td.when((repository as any)[methodName](), { ignoreExtraArgs: true }).thenThrow(error);

                await (restOfTest as Test)
                    .set(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))
                    .set(XSRF_TOKEN_HEADER_NAME, theSession.xsrfToken)
                    .set('Origin', 'core')
                    .expect(statusCode)
                    .expect('Content-Type', 'application/json; charset=utf-8')
                    .expect('Transfer-Encoding', 'chunked')
                    .expect('Content-Encoding', 'gzip')
                    .expect('Vary', 'Accept-Encoding')
                    .expect('Connection', 'close')
                    .then(response => {
                        expect(response.header).contain.keys('content-type', 'date', 'connection', 'transfer-encoding', 'content-encoding', 'vary');
                        expect(Object.keys(response.header)).has.length(6);

                        expect(response.text).to.have.length(0);
                    });
            });
        }
    }
});
