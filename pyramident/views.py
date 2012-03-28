from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from openid.extensions import sreg
from openid.extensions import pape
from openid.fetchers import HTTPFetchingError
from openid.server.server import EncodingError
from openid.server.server import ProtocolError
from openid.server.server import Server
from openid.server.trustroot import verifyReturnTo
from openid.store.filestore import FileOpenIDStore
from openid.yadis.constants import YADIS_CONTENT_TYPE
from openid.yadis.discover import DiscoveryFailure
from pyramid.response import Response
from pyramid.view import view_config
from pyramid_chameleon import render_template_to_response


#
# View functions
#
@view_config(route_name='home', renderer='templates/home.pt')
def home(request):
    return {'user_url': request.route_url('idPage'),
            'server_xrds_url': request.route_url('idpXrds'),
           }


@view_config(route_name='idpXrds', renderer='templates/xrds.pt')
def idpXrds(request):
    request.response_content_type = YADIS_CONTENT_TYPE
    return {'type_uris': [OPENID_IDP_2_0_TYPE],
            'endpoint_urls': [request.route_url('endpoint')],
           }


@view_config(route_name='idPage', renderer='templates/idPage.pt')
def idPage(request):
    return {'server_url': request.route_url('endpoint'),
           }


@view_config(route_name='endpoint', renderer='templates/endpoint.pt')
def endpoint(request):
    s = getServer(request)
    # First, decode the incoming request into something the OpenID
    # library can use.
    try:
        openid_request = s.decodeRequest(request.params)
    except ProtocolError as why:
        # This means the incoming request was invalid.
        return {'error': str(why)}

    # If we did not get a request, display text indicating that this
    # is an endpoint.
    if openid_request is None:
        return {}

    # We got a request; if the mode is checkid_*, we will handle it by
    # getting feedback from the user or by checking the session.
    if openid_request.mode in ["checkid_immediate", "checkid_setup"]:
        # If the request was an IDP-driven identifier selection request
        # (i.e., the IDP URL was entered at the RP), then return the
        # default identity URL for this server. In a full-featured
        # provider, there could be interaction with the user to determine
        # what URL should be sent.
        if not openid_request.idSelect():
            id_url = request.route_url('idPage')

            # Confirm that this server can actually vouch for that
            # identifier
            if id_url != openid_request.identity:
                # Return an error response
                raise ProtocolError(openid_request.message,
                                    "This server cannot verify the URL %r" %
                                    openid_request.identity)

        if openid_request.immediate:
            # Always respond with 'cancel' to immediate mode requests
            # because we don't track information about a logged-in user.
            # If we did, then the answer would depend on whether that user
            # had trusted the request's trust root and whether the user is
            # even logged in.
            openid_response = openid_request.answer(False)
            return displayResponse(request, openid_response)

        # Store the incoming request object in the session so we can
        # get to it later.
        setRequest(request, openid_request)
        return showDecidePage(request, openid_request)

    # We got some other kind of OpenID request, so we let the
    # server handle this.
    openid_response = s.handleRequest(openid_request)
    return displayResponse(request, openid_response)


@view_config(route_name='trustPage', renderer='templates/trustPage.pt')
def trustPage(request):
    return {'trust_handler_url': request.route_url('processTrustResult'),
           }


@view_config(route_name='processTrustResult',
             renderer='templates/processTrustResult.pt')
def processTrustResult(request):
    # Get the request from the session so we can construct the
    # appropriate response.
    openid_request = getRequest(request)

    # The identifier that this server can vouch for
    response_identity = request.route_url('idPage')

    # If the decision was to allow the verification, respond
    # accordingly.
    allowed = 'allow' in request.POST

    # Generate a response with the appropriate answer.
    openid_response = openid_request.answer(allowed,
                                            identity=response_identity)

    # Send Simple Registration data in the response, if appropriate.
    if allowed:
        sreg_data = {
            'fullname': 'Example User',
            'nickname': 'example',
            'dob': '1970-01-01',
            'email': 'invalid@example.com',
            'gender': 'F',
            'postcode': '12345',
            'country': 'ES',
            'language': 'eu',
            'timezone': 'America/New_York',
            }

        sreg_req = sreg.SRegRequest.fromOpenIDRequest(openid_request)
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        openid_response.addExtension(sreg_resp)

        pape_response = pape.Response()
        pape_response.setAuthLevel(pape.LEVELS_NIST, 0)
        openid_response.addExtension(pape_response)

    return displayResponse(request, openid_response)

#
#   Helper functions.
#
def setRequest(request, openid_request):
    """
    Store the openid request information in the session.
    """
    if openid_request:
        request.session['openid_request'] = openid_request
    else:
        request.session['openid_request'] = None


def getRequest(request):
    """
    Get an openid request from the session, if any.
    """
    return request.session.get('openid_request')


def getOpenIDStore(filestore_path, table_prefix):
    """ Return an OpenID association store object.
    """
    return FileOpenIDStore(filestore_path)


FILESTORE_PATH = '/tmp/pyramident_s_store'  #XXX make this configurable

def getServer(request):
    """ Get a Server object to perform OpenID authentication.
    """
    return Server(FileOpenIDStore(FILESTORE_PATH),
                  request.route_url('endpoint'))


def displayResponse(request, openid_response):
    """ Display an OpenID response.
    
    Errors will be displayed directly to the user.

    Successful responses and other protocol-level messages will be sent
    using the proper mechanism (i.e., direct response, redirection, etc.).
    """
    s = getServer(request)

    # Encode the response into something that is renderable.
    try:
        webresponse = s.encodeResponse(openid_response)
    except EncodingError as why:
        # If it couldn't be encoded, display an error.
        text = why.response.encodeToKVForm()
        return render_template_to_response('templates/endpoint.pt',
                                           error=text)

    # Construct and return a response onbject
    r = Response(body=webresponse.body)
    r.status = webresponse.code #XXX int vs. str?

    for header, value in webresponse.headers.iteritems():
        r.headers[header] = value

    return r


def showDecidePage(request, openid_request):
    """ Render a page to the user so a trust decision can be made.

    @type openid_request: openid.server.server.CheckIDRequest
    """
    trust_root = openid_request.trust_root
    return_to = openid_request.return_to

    try:
        # Stringify because template's ifequal can only compare to strings.
        if verifyReturnTo(trust_root, return_to):
            trust_root_valid = "Valid"
        else:
            trust_root_valid = "Invalid"
    except DiscoveryFailure as err:
        trust_root_valid = "DISCOVERY_FAILED"
    except HTTPFetchingError as err:
        trust_root_valid = "Unreachable"

    pape_request = pape.Request.fromOpenIDRequest(openid_request)

    pTR = request.route_url('processTrustResult')
    return render_template_to_response('templates/trustPage.pt',
                                       trust_root=trust_root,
                                       trust_handler_url=pTR,
                                       trust_root_valid=trust_root_valid,
                                       pape_request=pape_request,
                                      )
