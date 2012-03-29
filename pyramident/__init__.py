from pyramid.session import UnencryptedCookieSessionFactoryConfig
my_session_factory = UnencryptedCookieSessionFactoryConfig('itsaseekreet')

from pyramid.config import Configurator

def main(global_config, **settings):
    """ Return a Pyramid WSGI application.
    """
    config = Configurator(settings=settings,
                          session_factory=my_session_factory)
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('home', '/')
    config.add_route('idpXrds', '/xrds'),
    config.add_route('idPage', '/user'),
    config.add_route('endpoint', '/endpoint'),
    config.add_route('trustPage', '/trust'),
    config.add_route('processTrustResult', '/processTrustResult'),
    config.scan()
    return config.make_wsgi_app()
