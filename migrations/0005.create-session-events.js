exports.up = (knex, Promise) => knex.schema.raw(`
    CREATE TABLE identity.session_events (
        -- Primary key
        id Serial,
        PRIMARY KEY (id),
        -- Core properties
        type SmallInt NOT NULL,
        timestamp Timestamp NOT NULL,
        data Jsonb NULL,
        -- Foreign key
        session_id Uuid NOT NULL REFERENCES identity.sessions(id)
    );

    CREATE INDEX session_events_session_id ON identity.session_events(session_id);
`);

exports.down = (knex, Promise) => knex.schema.raw(`
    DROP INDEX IF EXISTS identity.session_event_session_id;
    DROP TABLE IF EXISTS identity.session_event;
`);
