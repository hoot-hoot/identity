module.exports = {
    client: 'pg',
    connection: {
        host: process.env.POSTGRES_HOST,
        port: process.env.POSTGRES_PORT,
        database: process.env.POSTGRES_DATABASE,
        user: process.env.IDENTITY_DATABASE_USERNAME,
        password: process.env.IDENTITY_DATABASE_PASSWORD
    },
    pool: {
        min: 2,
        max: 10
    },
    migrations: {
        directory: process.env.IDENTITY_DATABASE_MIGRATIONS_DIR,
        tableName: process.env.IDENTITY_DATABASE_MIGRATIONS_TABLE
    }
}
