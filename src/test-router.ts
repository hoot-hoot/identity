import { wrap } from 'async-middleware'
import * as compression from 'compression'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'

import {
    newCommonApiServerMiddleware,
    newLocalCommonServerMiddleware,
    Request
} from '@truesparrow/common-server-js'

import { AppConfig } from './app-config'
import { Repository } from './repository'


export function newTestRouter(config: AppConfig, repository: Repository): express.Router {
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

    return testRouter;
}
