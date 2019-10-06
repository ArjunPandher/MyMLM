from app import app, db
from flask import render_template, flash, redirect, url_for, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from app.forms import LoginForm, RegistrationForm, EditProfileForm, CreateSchemeForm, MessageForm
from app.models import User, Scheme, Message, Notification
from werkzeug.urls import url_parse
from flask import request
from datetime import datetime


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = CreateSchemeForm()
    if form.validate_on_submit():
        scheme = Scheme(title=form.title.data, description=form.description.data, top_user=current_user,
                        cost=int(form.minimum.data))
        current_user.funds = current_user.funds - scheme.cost
        db.session.add(scheme)
        db.session.commit()
        current_user.add_scheme(scheme)
        db.session.commit()
        flash('Your investment opportunity has been posted!')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    schemes = Scheme.query.order_by(Scheme.timestamp.desc()).paginate(page, app.config['SCHEMES_PER_PAGE'], False)
    next_url = url_for('index', page=schemes.next_num) if schemes.has_next else None
    prev_url = url_for('index', page=schemes.prev_num) if schemes.has_prev else None
    return render_template('index.html', form=form, schemes=schemes.items, next_url=next_url, prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            return redirect(url_for('index'))
        return redirect(next_page)
    return render_template('login.html', title='Log In', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    message_form = MessageForm()
    if message_form.validate_on_submit():
        message = Message(author=current_user, recipient=user, body=message_form.message.data)
        db.session.add(message)
        db.session.commit()
        user.add_notification('unread_message_count', user.new_messages())
        db.session.commit()
        flash('Your message has been sent!')
        return redirect(url_for('user', username=username))


    page = request.args.get('page', 1, type=int)
    schemes = user.schemes.order_by(Scheme.timestamp.desc()).paginate(page, app.config['SCHEMES_PER_PAGE'], False)
    next_url = url_for('index', page=schemes.next_num) if schemes.has_next else None
    prev_url = url_for('index', page=schemes.prev_num) if schemes.has_prev else None

    return render_template('user.html', user=user, schemes=schemes.items, next_url=next_url, prev_url=prev_url,
                           form=message_form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form)


@app.route('/contributions')
@login_required
def contributions():
    page = request.args.get('page', 1, type=int)
    schemes = current_user.schemes.order_by(Scheme.timestamp.desc()).paginate(page, app.config['SCHEMES_PER_PAGE'],
                                                                              False)
    next_url = url_for('index', page=schemes.next_num) if schemes.has_next else None
    prev_url = url_for('index', page=schemes.prev_num) if schemes.has_prev else None

    return render_template('contributions.html', schemes=schemes.items, next_url=next_url, prev_url=prev_url)


@app.route('/messages')
@login_required
def messages():
    current_user.last_message_read_time = datetime.utcnow()
    current_user.add_notification('unread_message_count', 0)
    db.session.commit()
    page = request.args.get('page', 1, type=int)
    messages = current_user.messages_received.order_by(Message.timestamp.desc())\
        .paginate(page, app.config['SCHEMES_PER_PAGE'], False)
    next_url = url_for('messages', page=messages.next_num) if messages.has_next else None
    prev_url = url_for('messages', page=messages.prev_num) if messages.has_prev else None
    return render_template('messages.html', messages=messages.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/join/<scheme_id>')
@login_required
def join(scheme_id):
    scheme = Scheme.query.filter_by(id=scheme_id).first_or_404()
    if current_user.funds >= scheme.cost:
        new_scheme = Scheme(title=scheme.title, description=scheme.description, top_user=current_user, parent=scheme,
                            cost=scheme.cost)
        current_user.funds = current_user.funds - scheme.cost
        scheme.top_user.funds = scheme.top_user.funds + scheme.cost
        db.session.add(new_scheme)
        db.session.commit()
        current_user.add_scheme(scheme)
        current_user.add_scheme(new_scheme)
        db.session.commit()
        flash('You have successfully participated in this venture!')
    else:
        flash('You do not have enough funds to invest in this venture.')
    return redirect(url_for('index'))


@app.route('/view/<scheme_id>')
@login_required
def view_scheme(scheme_id):
    scheme = Scheme.query.filter_by(id=scheme_id).first_or_404()
    return render_template('view_scheme.html', scheme=scheme)


@app.route('/add_funds/<amount>')
@login_required
def add_funds(amount):
    current_user.funds = current_user.funds + int(amount)
    db.session.commit()
    flash('You have successfully added funds to your account!')
    return redirect(url_for('index'))


@app.route('/notifications')
@login_required
def notifications():
    since = request.args.get('since', 0.0, type=float)
    notifications = current_user.notifications.filter(Notification.timestamp > since).\
        order_by(Notification.timestamp.asc())
    return jsonify([{
        'name': n.name,
        'data': n.get_data(),
        'timestamp': n.timestamp
    } for n in notifications])

