import flask_login

from flask_login import current_user, logout_user, login_required, login_user

from flask import url_for, redirect, request, render_template, session, make_response
from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from airflow import models, configuration
from airflow.configuration import AirflowConfigException
from airflow.utils.db import provide_session
from airflow.utils.log.logging_mixin import LoggingMixin
from airflow.www.app import csrf

log = LoggingMixin().log


def get_config_param(param):
    return str(configuration.conf.get('saml_auth', param))


class SAMLUser(models.User):

    def __init__(self, user):
        self.user = user

    @property
    def is_active(self):
        """Required by flask_login"""
        return True

    @property
    def is_authenticated(self):
        """Required by flask_login"""
        return True

    @property
    def is_anonymous(self):
        """Required by flask_login"""
        return False

    def get_id(self):
        """Returns the current user id as required by flask_login"""
        return self.user.get_id()

    def data_profiling(self):
        """Provides access to data profiling tools"""
        return True

    def is_superuser(self):
        """Access all the things"""
        return True


class AuthenticationError(Exception):
    pass


class SAMLAuthBackend:

    def __init__(self):
        self.login_manager = flask_login.LoginManager()
        self.login_manager.login_view = 'airflow.login'
        self.login_manager.session_protection
        self.flask_app = None
        self.api_url = None

    def prepare_flask_request(self,request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'request_uri': '/saml/login',
            'server_port': url_data.port,
            'script_name': request.path,
            'get_data': request.args.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'post_data': request.form.copy()
        }

    def init_saml_auth(self,req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=get_config_param('saml_path'))
        return auth

    def init_app(self, flask_app):
        self.flask_app = flask_app

        self.login_manager.init_app(self.flask_app)

        self.login_manager.user_loader(self.load_user)

        # metadata file route
        self.flask_app.add_url_rule('/saml/metadata.xml',
                            'metadata',
                            self.metadata)

        # sso login uri
        self.flask_app.add_url_rule('/saml/login',
                            'saml_login',
                            self.saml_login,methods=["GET","POST"])

    def login(self, request):
        return redirect(url_for('saml_login'),)

    def logout(self, request):
        return redirect(url_for('saml_logout'))

    @provide_session
    @csrf.exempt
    def saml_logout(self, session=None):
        username = auth.get_nameid()
        email = auth.get_nameid()
        user = session.query(models.User).filter(
            models.User.username == username).first()

        if user:
            session.expunge(user)
            session.commit()
            logout_user(SAMLUser(user))
            session.commit()
            log.info("removed user {0} from the session and logged out of flask".format(username))
        else:
            log.info("Found no user in session for username {0} to expunge".format(username))
        
        return redirect(auth.logout(return_to=url_for('airflow.noaccess'),name_id=username))


    @provide_session
    @csrf.exempt
    def saml_login(self, session=None):
        req = self.prepare_flask_request(request)
        auth = self.init_saml_auth(req)
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False
        log.info("initiating login")
        log.info("request: {0}".format(request))

        if 'sso' in request.args:
            log.info("hit sso")
            return redirect(auth.login())
        elif len(request.args) == 0 or 'sso2' in request.args:
            log.info("hit sso2")
            return_to = '%sadmin/' % request.host_url
            return redirect(auth.login(return_to))
        elif 'slo' in request.args:
            log.info("hit slo")
            return redirect(url_for('saml_logout'))
        elif 'acs' in request.args:
            log.info("hit acs")
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                # session['samlUserdata'] = auth.get_attributes()
                # session['samlNameId'] = auth.get_nameid()
                # session['samlSessionIndex'] = auth.get_session_index()
                # stuff for flask_login
                username = auth.get_nameid()
                email = auth.get_nameid()
                log.info("no errors")
                user = session.query(models.User).filter(
                    models.User.username == username).first()
                log.info("user query done")

                if not user:
                    user = models.User(
                        username=username,
                        email=email,
                        is_superuser=True)

                session.merge(user)
                session.commit()
                login_user(SAMLUser(user))
                session.commit()
                log.info("committed user")
                # end stuff for flask_login
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                if 'RelayState' in request.form and self_url != request.form['RelayState']:
                    return redirect(auth.redirect_to(request.form['RelayState']))
        elif 'sls' in request.args:
            log.info("hit sls")
            return redirect(url_for('saml_logout'))

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        if not paint_logout:
            return redirect(url_for('airflow.noaccess'))
        else:
            return request.args.get('state') or url_for('admin.index')

    def metadata(self):
        req = self.prepare_flask_request(request)
        auth = self.init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'
        else:
            resp = make_response(', '.join(errors), 500)
        return resp

    @provide_session
    def load_user(self, userid, session=None):
        if not userid or userid == 'None':
            return None

        user = session.query(models.User).filter(
            models.User.id == int(userid)).first()
        return SAMLUser(user)

login_manager = SAMLAuthBackend()

def login(self, request):
    return login_manager.login(request)

def logout(self, request):
    return login_manager.logout(request)
