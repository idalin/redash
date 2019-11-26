import logging
import requests
from flask import redirect, url_for, Blueprint, flash, request, session
from flask_oauthlib.client import OAuth

from redash import models, settings
from redash.authentication import create_and_login_user, logout_and_redirect_to_index, get_next_path
from redash.authentication.org_resolving import current_org

logger = logging.getLogger('generic_oauth')

oauth = OAuth()
blueprint = Blueprint('generic_oauth', __name__)


def generic_remote_app():
    if 'generic' not in oauth.remote_apps:
        oauth.remote_app('generic',
                         base_url=settings.GENERIC_OAUTH_BASE_URL,
                         authorize_url=settings.GENERIC_OAUTH_AUTH_URL,
                         request_token_url=None,
                         request_token_params={
                             'scope': settings.GENERIC_OAUTH_SCOPES,
                         },
                         access_token_url=settings.GENERIC_OAUTH_TOKEN_URL,
                         access_token_method='POST',
                         consumer_key=settings.GENERIC_OAUTH_CLIENT_ID,
                         consumer_secret=settings.GENERIC_OAUTH_CLIENT_SECRET)

    return oauth.generic


def get_user_profile(access_token):
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = requests.get(settings.GENERIC_OAUTH_API_URL, headers=headers)

    if response.status_code == 401:
        logger.warning("Failed getting user profile (response code 401).")
        return None

    return response.json()


def verify_profile(org, profile):
    if org.is_public:
        return True

    email = profile['email']
    domain = email.split('@')[-1]

    # if domain in org.google_apps_domains:
    #     return True

    if org.has_user(email) == 1:
        return True

    return False


@blueprint.route('/<org_slug>/oauth/generic', endpoint="authorize_org")
def org_login(org_slug):
    session['org_slug'] = current_org.slug
    return redirect(url_for(".authorize", next=request.args.get('next', None)))


@blueprint.route('/oauth/generic', endpoint="authorize")
def login():
    callback = url_for('.callback', _external=True)
    next_path = request.args.get('next', url_for("redash.index", org_slug=session.get('org_slug')))
    logger.info("Callback url: %s", callback)
    logger.info("Next is: %s", next_path)
    return generic_remote_app().authorize(callback=callback, state=next_path)


@blueprint.route('/oauth/generic_callback', endpoint="callback")
def authorized():
    resp = generic_remote_app().authorized_response()
    logger.info("resp is %s",resp)
    access_token = resp['access_token']

    if access_token is None:
        logger.warning("Access token missing in call back request.")
        flash("Validation error. Please retry.")
        return redirect(url_for('redash.login'))

    profile = get_user_profile(access_token)
    if profile is None:
        flash("Validation error. Please retry.")
        return redirect(url_for('redash.login'))

    if 'org_slug' in session:
        org = models.Organization.get_by_slug(session.pop('org_slug'))
    else:
        org = current_org

    if not verify_profile(org, profile):
        logger.warning("User tried to login with unauthorized domain name: %s (org: %s)", profile['email'], org)
        flash("Your generic oauth account ({}) isn't allowed.".format(profile['email']))
        return redirect(url_for('redash.login', org_slug=org.slug))

    picture_url = "%s?sz=40" % profile['picture']
    user = create_and_login_user(org, profile['name'], profile['email'], picture_url)
    if user is None:
        return logout_and_redirect_to_index()

    unsafe_next_path = request.args.get('state') or url_for("redash.index", org_slug=org.slug)
    next_path = get_next_path(unsafe_next_path)

    return redirect(next_path)
