module.exports = {
    client: 'pg',
    connection: process.env.IDENTITY_DATABASE_URL,
    pool: {
        min: 2,
        max: 10
    },
    migrations: {
        directory: process.env.IDENTITY_DATABASE_MIGRATIONS_DIR,
        tableName: process.env.IDENTITY_DATABASE_MIGRATIONS_TABLE
    }
}
