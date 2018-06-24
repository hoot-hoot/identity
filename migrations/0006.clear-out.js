exports.up = (knex, Promise) => knex.schema.raw(`
    DELETE FROM identity.session_events;
    DELETE FROM identity.sessions;
    DELETE FROM identity.user_events;
    DELETE FROM identity.users;
`);

exports.down = (knex, Promise) => knex.schema.raw(`
`);
