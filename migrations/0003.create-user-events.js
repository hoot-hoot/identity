exports.up = (knex, Promise) => knex.schema.raw(`
    CREATE TABLE identity.user_events (
        -- Primary key
        id Serial,
        PRIMARY KEY (id),
        -- Core properties
        type SmallInt NOT NULL,
        timestamp Timestamp NOT NULL,
        data Jsonb NULL,
        -- Foreign key
        user_id Int NOT NULL REFERENCES identity.users(id)
    );

    CREATE INDEX user_events_user_id ON identity.user_events(user_id);
`);

exports.down = (knex, Promise) => knex.schema.raw(`
    DROP INDEX IF EXISTS identity.user_events_user_id;
    DROP TABLE IF EXISTS identity.user_events;
`);
