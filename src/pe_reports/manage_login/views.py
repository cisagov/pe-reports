# Local packages
import itsdangerous

from pe_reports.manage_login.models import User
from pe_reports import db, app

#PE-Reports import forms
from pe_reports.manage_login.forms import (LoginForm,
                                           RegistrationForm,
                                           RequestRestForm,
                                           ResetPasswordForm)

#Third party packages
from flask import render_template, flash, redirect, url_for, Blueprint, request
from flask_login import login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


manage_login_blueprint = Blueprint(
    "manage_login", __name__, template_folder="templates/manage_login")


@manage_login_blueprint.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Logout user and redirect to home with login/register displayed."""
    logout_user()
    flash('You are logged out!', 'success')
    return redirect(url_for('index'))


@manage_login_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()

            if user.check_password(form.password.data) and user is not None:

                login_user(user)
                flash(f'{user.username} you have logged in successfully!', 'success')

                next = request.args.get('next')

                if next is None or not next[0] == '/':
                    next = url_for('index')

                return redirect(next)
    except AttributeError:
        flash('The user name or password that you have entered is incorrect, please try again.', 'warning')

    return render_template('login.html', form=form)


@manage_login_blueprint.route('/register', methods=['GET','POST'])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data

                    )
        print(user)

        db.session.add(user)
        db.session.commit()

        flash('Thanks for your registration!', 'success')
        return redirect(url_for('manage_login.login'))
    # else:
    #     user = User(email=form.email.data,
    #                 username=form.username.data,
    #                 password=form.password.data
    #
    #                 )
    #     print(user.password_hash)

    return render_template('register.html', form=form)


def get_reset_token(self, expires_sec=1800):
    # user = User.query.filter_by(username='cduhn75').first()
    s = Serializer(app.config['SECRET_KEY'], expires_sec)

    return s.dumps({"user_id": self.username}).decode('utf-8')

@staticmethod
def verify_reset_token(token):

    s = Serializer(app.config['SECRET_KEY'])

    try:
        user_id = s.loads(token)['user_id']

    except itsdangerous.SignatureExpired:
        return None

    return User.query.get(user_id)

def send_reset_email():
    pass


@manage_login_blueprint.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestRestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with '
              'instructions to reset your password.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_request.html',
                           title='Reset Password',
                           form=form)


@manage_login_blueprint.route('/reset_password/<token>',
                              methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token." , 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    return render_template('reset_token.html',
                           title='Reset Password',
                           form=form)








