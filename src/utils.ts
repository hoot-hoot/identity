/** Defines some helpers. */

/** Imports. Also so typedoc works correctly. */
import { MarshalFrom } from 'raynor'

import { Request } from '@truesparrow/common-server-js'
import { XsrfTokenMarshaller } from '@truesparrow/identity-sdk-js/entities'
import {
    SESSION_TOKEN_HEADER_NAME,
    XSRF_TOKEN_HEADER_NAME
} from '@truesparrow/identity-sdk-js/client'
import { SessionToken } from '@truesparrow/identity-sdk-js/session-token'


const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
const xsrfTokenMarshaller = new XsrfTokenMarshaller();


export function extractSessionToken(req: Request): SessionToken | null {
    let sessionTokenSerialized: string | null = null;

    if (req.header(SESSION_TOKEN_HEADER_NAME) != undefined) {
        sessionTokenSerialized = req.header(SESSION_TOKEN_HEADER_NAME) as string;
    } else {
        return null;
    }

    try {
        return sessionTokenMarshaller.extract(JSON.parse(sessionTokenSerialized as string));
    } catch (e) {
        return null;
    }
}

export function extractXsrfToken(req: Request): string | null {
    try {
        const xsrfTokenRaw = req.header(XSRF_TOKEN_HEADER_NAME);
        return xsrfTokenMarshaller.extract(xsrfTokenRaw);
    } catch (e) {
        return null;
    }
}
