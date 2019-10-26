
APP_NAME = 'rw-client-dreamers'
APP_VERSION = '0.0.0'

LOG_PATTERN = '%(asctime)s.%(msecs)s:%(name)s:%(thread)d:%(levelname)s:%(process)d:%(message)s'

PASSWORD_AES_ENCRYPTION = 'MyS3cr3tP455w0rd'
EXTENSION_AES_ENCRYPTION = 'crypted'

FILTER_FILE_EXTENSIONS_ACTIVE = True

FILTER_FILE_EXTENSIONS = [
    'txt', 'pdf'
]

CONF_DEBUG = {
    'roads': [
        '/home/diego/PycharmProjects/rw-client/tests/treasures_examples/',
    ],
}

CONF_PRODUCTION = {
    'linux': {
        'roads': [
            '/root/',
            '/home/',
        ],
    },

}