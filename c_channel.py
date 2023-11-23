from flask import session, g, redirect, url_for, request, flash, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import random
import string
import os

import tools


LOCKED = False
DISABLE_POST = False

UPLOAD_FOLDER = tools.inst("uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_CHARS = string.printable
c = "Under construction"

bp = tools.MyBlueprint("channel", host="cch.act25.com", db="channel")


"""
MOD/ADMIN LEVELS
-------------
0 - useless
1 - can use VIP board
2 - can ban/delete/watchlist but not see ips
3 - can comment as an admin
4 - can see ips
5 - can see logs
6 - can manage admins
7 - can use ULTRA board
8 - can manage boards
9 - can edit watchlist, logs, etc
"""


class Ban:
    def __init__(self, ip: str, reason: str, given: int, expires: int, board: str):
        self.ip = ip
        self.reason = reason
        self.given = given
        self.expires = expires
        self.board = board

        if not self.expires:
            self.expires = "NEVER"

        self.sitewide = not bool(self.board)

    def is_expired(self) -> bool:
        if self.expires == "NEVER":
            return False

        if tools.ts_now() >= self.expires:
            return True
        else:
            return False
        
    def delete(self) -> bool:
        g.cur.execute(
            "DELETE FROM bans WHERE ip = ?;",
            (self.ip,)
        )
        return True


class Board:
    def __init__(self, name: str, title: str, description: str, css_file: str = None, rules: str = None):
        self.name = name
        self.title = title
        self.description = description
        self.css_file = css_file
        self.rules = rules


class Post:
    def __init__(self, post_id: int, board: str, thread: int, old_filename: str, filename: str, filesize: str, fileres: str, comment: str, subject: str, author: str, mod_id: int, parent: int, pinned: int, locked: int, time: int, bump: int, ip: str, deletion: str, deletion_time: int):
        self.id = post_id
        self.board = board
        self.is_thread = bool(thread)
        self.original_filename = old_filename
        self.filename = filename
        self.file_size = filesize
        self.file_res = fileres
        self.comment = comment
        self.subject = subject
        self.author = author
        self.mod_id = mod_id
        self.parent_id = parent
        self.is_pinned = bool(pinned)
        self.is_locked = bool(locked)
        self.time = time
        self.last_bump = bump
        self.deletion_reason = deletion
        self.deletion_time = deletion_time
        self.replies = []


class User:
    def __init__(self, uid: int, username: str, level: int):
        self.id = uid
        self.name = username
        self.level = level


class WatchedIP:
    def __init__(self, ip: str, ban_hours: int, site_bans: int, board_bans: int, first_banned: int, last_banned: int, reasons: str, note: str):
        self.ip = ip
        self.ban_hours = ban_hours
        self.site_bans = site_bans
        self.board_bans = board_bans
        self.first_banned = first_banned
        self.last_banned = last_banned
        self.reasons = reasons.split(";")
        self.note = note


class LogItem:
    def __init__(self, log_id: int, ip: str, user: int, action: str, description: str, time: int):
        self.id = log_id
        self.ip = ip
        self.user = user
        self.action = action
        self.description = description
        self.time = time

    
def get_board(board_name: str, *, dont_handle: bool = False):
    board_data = g.cur.execute(
        "SELECT title, description, css_file, rules FROM boards WHERE name = ?;",
        (board_name,)
    ).fetchone()

    if board_data:
        board = Board(board_name, *board_data)
        return board
    
    else:
        return None


def get_threads(board_name: str, *, search: str = None):
    search_insert = ""
    replacements = (board_name,)

    if search:
        search_insert = "AND (comment LIKE %?% OR subject LIKE %?% OR author LIKE %?%) "
        replacements += (search,) * 3

    posts_data = g.cur.execute(
        f"SELECT * FROM posts WHERE board = ? AND deletion IS NULL {search_insert}ORDER BY bump DESC;",
        replacements
    ).fetchall()

    posts = []
    threads = []

    for post_data in posts_data:
        posts.append(Post(*post_data))

    for post in posts:
        if post.is_thread:
            for post2 in posts:
                if post2.parent_id == post.id:
                    post.replies.append(post2)
            threads.append(post)

    return threads


def get_thread(board_name: str, thread_id: int):
    top_post_data = g.cur.execute(
        "SELECT * FROM posts WHERE id = ? AND deletion IS NULL;",
        (thread_id,)
    ).fetchone()
    
    if not top_post_data: 
        return bp.render("thread_nf.html", board_name=board_name, thread_id=thread_id)
    
    top_post = Post(*top_post_data)

    if top_post.board != board_name: 
        return redirect(url_for("channel.thread", board_name=top_post.board, thread_id=top_post.id))

    replies_data = g.cur.execute(
        "SELECT * FROM posts WHERE parent = ? AND deletion IS NULL ORDER BY time DESC;",
        (top_post.id,)
    ).fetchall()

    for reply_data in replies_data:
        top_post.replies.append(Post(*reply_data))

    return top_post


def allowed_file(filename):
    if not ("." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS):
        return False
    for char in filename:
        if char not in ALLOWED_CHARS:
            return False
        
    return True


def ra(required_level: int = 0):
    if "user_id" not in session:
        return "You must login to view this page.", "channel.login"

    level = g.cur.execute(
        "SELECT level FROM users WHERE id = ?;",
        (session["user_id"],)
    ).fetchone()

    if not level:
        session.clear()
        return "Account not found.", "channel.login"

    level = level[0]

    if level < required_level:
        return "You do not have sufficient permissions to view this page.", "channel.dashboard"


def ae(error: tuple):
    message, endpoint = error
    flash(message)
    return redirect(url_for(endpoint))


def get_user():
    if not "user_id" in session:
        return None

    user_data = g.cur.execute(
        "SELECT id, username, level FROM users WHERE id = ?;",
        (session["user_id"],)
    ).fetchone()

    if not user_data:
        return None

    return User(*user_data)


def rip_and_tear(class_, query: str, *, inserts: tuple = None):
    if inserts:
        datas = g.cur.execute(query, inserts)
    else:
        datas = g.cur.execute(query)
    
    results = []

    for data in datas:
        results.append(class_(*data))

    return results


@bp.before_request
def before_request():
    if LOCKED:
        allow_access = False
        if "user_id" in session:
            admin_level = g.cur.execute(
                "SELECT level FROM users WHERE id = ?;",
                (session["user_id"],)
            ).fetchone()[0]

            if admin_level > 0:
                allow_access = True

        if request.endpoint in ["channel.locked", "channel.login_handler"]:
            allow_access = True

        if (not allow_access):
            return redirect(url_for("channel.locked"))
        
    ip = request.headers.get("CF-Connecting-IP")

    ban_data = g.cur.execute(
        "SELECT reason, given, expires, board FROM bans WHERE ip = ? ORDER BY expires DESC;",
        (ip,)
    ).fetchone()

    if ban_data:
        ban = Ban(ip, *ban_data)

        if ban.is_expired():
            ban.delete()
            flash(f"Your ban from {tools.ts_format(ban.given, '%b %-d %-I:%M%p')} for the reason of \"{ban.reason}\" has expired.", "pos")

        else:
            return bp.render("banned.html", ban=ban)


@bp.route("/")
@bp.route("/home")
def home():
    boards_data = g.cur.execute(
        "SELECT * FROM boards;",
    ).fetchall()

    boards = []
    for board_data in boards_data:
        boards.append(Board(*board_data))

    return bp.render("home.html", boards=boards)


@bp.route("/locked")
def locked():
    if LOCKED:
        return bp.render("locked.html", session_id=session.get("user_id"))
    else:
        return redirect(url_for("channel.home"))


@bp.route("/rules")
def rules():
    return bp.render("global_rules.html")


@bp.route("/<board_name>/")
def board(board_name):
    user = get_user()

    board = get_board(board_name)
    if not board: 
        return bp.render("board_nf.html", name=board_name)
    
    threads = get_threads(board_name)
    return bp.render("board.html", board=board, threads=threads, user=user)


@bp.route("/<board_name>/rules")
def board_rules(board_name):
    board = get_board(board_name)
    if not board: 
        return bp.render("board_nf.html", name=board_name)
    
    if not board.rules: 
        return bp.render("board_nr.html", name=board_name)
    
    return bp.render("board_rules.html", board=board)


@bp.route("/<board_name>/catalog")
def catalog(board_name):
    user = get_user()

    board = get_board(board_name)
    if not board: 
        return bp.render("board_nf.html", name=board_name)
    
    threads = get_threads(board_name)
    return bp.render("catalog.html", board=board, threads=threads, user=user)


@bp.route("/<board_name>/catalog/search/<query>")
def search_catalog(board_name, query):
    user = get_user()

    board = get_board(board_name)
    if not board: 
        return bp.render("board_nf.html", name=board_name)
    
    threads = get_threads(board_name, search=query)
    return bp.render("catalog.html", board=board, threads=threads, search=query, user=user)


@bp.route("/<board_name>/thread/<thread_id>")
def thread(board_name, thread_id):
    user = get_user()

    thread_post = get_thread(board_name, thread_id)
    if not isinstance(thread_post, Post):
        return thread_post

    return bp.render("thread.html", thread_post=thread_post, board_name=board_name, user=user)


@bp.route("/<board_name>/thread/<thread_id>/mention/<reply_id>")
def mention(board_name, thread_id, reply_id):
    user = get_user()

    top_post_or_return = get_thread(board_name, thread_id)
    if not isinstance(top_post_or_return, Post):
        return top_post_or_return

    found = False
    for reply in top_post_or_return.replies:
        if reply.id == reply_id:
            reply.replying_to = True
            found = True
            
        else:
            reply.replying_to = False

    replying = True
    if not found:
        flash("Sorry, an error occurred when replying.", "neg")
        replying = False

    return bp.render("thread.html", top_post=top_post_or_return, replying=replying, user=user)


@bp.route("/uploads/<filename>")
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


@bp.route("/admin")
def login():
    e = ra()

    if not e:
        return redirect(url_for("channel.dashboard"))

    session.clear()
    return bp.render("login.html")


@bp.route("/admin/dashboard")  # grid of 6 following options, also include link to VIP (Lvl.1), ULTRA (Lvl.7), and HYPER-EDITOR (Lvl.9)
def dashboard():
    if e := ra(): return ae(e)
    user = get_user()

    return bp.render("dashboard.html", user=user)


@bp.route("/admin/settings")
def settings():
    if e := ra(): return ae(e)
    user = get_user()

    return bp.render("settings.html", user=user)


@bp.route("/admin/listing")    # 1: compact list of all posts, button to go to deleted posts (Lvl.2)
def listing():
    if e := ra(2): return ae(e)
    user = get_user()

    q = "SELECT * FROM posts WHERE deletion IS NULL ORDER BY time DESC;"
    posts = rip_and_tear(Post, q)

    return bp.render("listing.html", user=user, posts=posts)


@bp.route("/admin/listing/deleted")    # 1: compact list of all deleted posts (Lvl.2)
def listing_deleted():
    if e := ra(2): return ae(e)
    user = get_user()

    q = "SELECT * FROM posts WHERE deletion IS NOT NULL ORDER BY time DESC;"
    posts = rip_and_tear(Post, q)

    return bp.render("listing.html", user=user, posts=posts, deleted=True)


@bp.route("/admin/bans")   # 2: list of bans (Lvl.2)
def bans():
    if e := ra(2): return ae(e)
    user = get_user()

    q = "SELECT * FROM bans ORDER BY given DESC;"
    bans = rip_and_tear(Ban, q)

    return bp.render("bans.html", user=user, bans=bans)


@bp.route("/admin/watchlist")  # 3: watchlist (Lvl.2)
def watchlist():
    if e := ra(2): return ae(e)
    user = get_user()

    q = "SELECT * FROM watchlist ORDER BY first_banned DESC;"
    watched = rip_and_tear(WatchedIP, q)

    return bp.render("watchlist.html", user=user, watched=watched)


@bp.route("/admin/logs")   # 4 : logs (Lvl.5)
def logs():
    if e := ra(5): return ae(e)
    user = get_user()

    q = "SELECT * FROM logs ORDER BY time DESC;"
    logs = rip_and_tear(LogItem, q)

    return bp.render("logs.html", user=user, logs=logs)


@bp.route("/admin/accounts")   # 5 : manage lower accounts (Lvl.6)
def manage_accounts():
    if e := ra(6): return ae(e)
    
    return c


@bp.route("/admin/boards") # 6 : manage boards (Lvl.8)
def manage_boards():
    if e := ra(8): return ae(e)
    
    return c


@bp.route("/admin/hyper")
def hyper_editor():
    if e := ra(9): return ae(e)
    
    return c


@bp.route("/sys/login", methods=["POST"])
def login_handler():
    username = request.form.get("username")
    password = request.form.get("password")

    r = redirect(request.referrer)

    user_data = g.cur.execute(
        "SELECT id, hash FROM users WHERE username = ?;",
        (username,)
    ).fetchone()

    if not user_data:
        flash("Incorrect username.")
        return r
    
    user_id, password_hash = user_data

    if not check_password_hash(password_hash, password):
        flash("Incorrect password.")
        return r
    
    session["user_id"] = user_id
    session.permanent = True

    if "lock" in request.referrer:
        redirep = "channel.home"
    else:
        redirep = "channel.dashboard"

    flash(f"You have logged in as {username}.", "pos")
    return redirect(url_for(redirep))


@bp.route("/sys/logout", methods=["POST", "GET"])
def logout_handler():
    session.clear()
    return redirect(url_for("channel.login"))


@bp.route("/sys/apply", methods=["POST"])
def apply_settings():
    return c


@bp.route("/sys/post", methods=["POST"])
def post_handler():
    board = request.form.get("board")
    is_thread = request.form.get("is-thread")
    author = request.form.get("author")
    subject = request.form.get("subject")
    comment = request.form.get("comment")
    mod_id = request.form.get("mod-id")
    parent = request.form.get("parent")
    pinned = request.form.get("pinned")
    locked = request.form.get("locked")

    if author: author = author.strip()
    if subject: subject = subject.strip()
    if comment: comment = comment.strip()

    r = redirect(request.referrer)

    if "file" not in request.files:
        flash("Error: File was not attached to request properly.")
        return r
    
    if DISABLE_POST:
        flash("Sorry, posting is disabled right now.")
        return r
    
    upload = request.files["file"]
    if not (upload.filename == "" or not upload):
        if not allowed_file(upload.filename):
            flash("This file is not supported.")
            return r
        
        else:
            filename = secure_filename(upload.filename)
    
    else:
        filename = None

    time = tools.ts_now()
    ip = request.headers.get("CF-Connecting-IP")

    if not (board and time and ip):
        flash("Error: Missing necessary included form data.")
        return r

    for item in [comment, subject, author]:
        if item:
            for char in item:
                if char not in ALLOWED_CHARS:
                    flash("Invalid characters detected. Use ASCII only!")
                    return r

    if comment and len(comment) > 1000:
        flash("Comment must not be more than 1000 characters in length.")
        return r
    
    if subject and len(subject) > 16:
        flash("Subject must not be more than 16 characters in length.")
        return r
    
    if author and len(author) > 16:
        flash("Author name must not be more than 16 characters in length.")
        return r

    if is_thread:
        if not filename:
            flash("You are required to upload an image to create new threads.")
            return r
        
        if not (subject or comment):
            flash("New threads must have a subject or comment.")
            return r
        
        if parent:
            flash("Error: New threads cannot have a parent.")
            return r

    else:
        if subject:
            flash("Replies cannot have a subject.")
            return r
        
        if (pinned or locked):
            flash("Replies cannot be pinned or locked.")
            return r

        if not (filename or comment):
            flash("Replies must have a filename or comment.")
            return r

    board_test = g.cur.execute(
        "SELECT title FROM boards WHERE name = ?;",
        (board,)
    ).fetchone()

    if not board_test:
        flash("Invalid board specified.")
        return r

    ban = g.cur.execute(
        "SELECT reason FROM bans WHERE ip = ? AND (board = ? OR board IS NULL);",
        (ip, board)
    ).fetchone()

    if ban:
        flash("You are banned. Check the home page for details.")
        return r
    
    do_pin = False
    do_lock = False

    if mod_id:
        if "user_id" in session:
            user_data = g.cur.execute(
                "SELECT level, username FROM users WHERE id = ?;",
                (session["user_id"],)
            ).fetchone()
            if user_data:
                level, username = user_data
                if level >= 3 and username:
                    author = username
                    if pinned:
                        do_pin = True
                    if locked:
                        do_lock = True
                    
                else:
                    flash("You have an insufficient admin level.")
                    return r
            else:
                flash("You are not an admin.")
                return r
        else:
            flash("You are not logged in as an admin.")
            return r

    if parent:
        parent_data = g.cur.execute(
            "SELECT thread, locked FROM posts WHERE id = ? AND board = ?;",
            (parent, board)
        ).fetchone()

        if not parent_data:
            flash("Invalid thread to reply to.")
            return r
        
        if parent_data[1]:
            flash("This thread is locked.")
            return r
    
    if not author:
        author = "anonymous"

    if is_thread:
        cooldown = 60
        check_thread = 1
        post_type = "thread"
    else:
        cooldown = 20
        check_thread = 0
        post_type = "reply"

    recent_thread = g.cur.execute(
        "SELECT time FROM posts WHERE thread = ? AND ip = ? AND time > ?;",
        (check_thread, ip, time-cooldown)
    ).fetchone()

    if recent_thread:
        flash(f"You need to wait {cooldown-(time-recent_thread[0])} seconds before posting another {post_type}. ({cooldown} sec cooldown)")
        return r

    duplicate_post = g.cur.execute(
        "SELECT id FROM posts WHERE subject = ? AND comment = ? AND old_filename = ?;",
        (subject, comment, filename)
    ).fetchone()

    if duplicate_post:
        flash(f"Your post seems identical to No. {duplicate_post[0]}.")
        return r

    extension = filename.split(".")[-1] if filename else None

    if extension:
        old_filename = filename
        filename = None
        new_filename = str(time) + str(random.randint(111111, 999999)) + "." + extension

        save_path = tools.path(UPLOAD_FOLDER, new_filename)

        upload.save(save_path)

        exact_size = os.path.getsize(save_path)

        if exact_size > 16 * 1024 * 1024:
            os.remove(save_path)
            flash("File must be smaller than 16 MB.")
            return r

        units = ["", "K", "M"]
        unit_index = 0
        while exact_size > 1024:
            exact_size = round(exact_size / 1024, 1)
            unit_index += 1

        general_size = str(exact_size)
        if general_size[-2:] == ".0":
            general_size = general_size.replace(".0", "")

        filesize = f"{general_size} {units[unit_index]}B"

        try:
            with Image.open(save_path) as img:
                image_width = img.width
                image_height = img.height

        except:
            os.remove(save_path)
            flash("File is not a valid image.")
            return r

        else:
            if image_height / image_width > 5:
                os.remove(save_path)
                flash("Your image's height to width ratio is too tall. (>5:1)")
                return r

            if image_width / image_height > 5:
                os.remove(save_path)
                flash("Your image's width to height ratio is too wide. (>1:5)")
                return r

            fileres = f"{image_width}x{image_height}px"
    
    else:
        old_filename = None
        new_filename = None
        filesize = None
        fileres = None

    is_thread = 1 if is_thread else 0
    pinned = 1 if pinned else 0
    locked = 1 if locked else 0

    if is_thread:
        bump = tools.ts_now()
    else:
        bump = None

    g.cur.execute(
        "INSERT INTO posts(board, thread, old_filename, filename, filesize, fileres, comment, subject, author, mod_id, parent, pinned, locked, time, bump, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (board, is_thread, old_filename, new_filename, filesize, fileres, comment, subject, author, mod_id, parent, do_pin, do_lock, time, bump, ip)
    )

    if parent:
        g.cur.execute(
            "UPDATE posts SET bump = ? WHERE id = ?;",
            (tools.ts_now(), parent)
        )

    flash(f"Your {'post' if is_thread else 'reply'} has been created", "pos")
    
    if is_thread:
        new_id = g.cur.execute("SELECT last_insert_rowid();").fetchone()
        if new_id: 
            new_id = new_id[0]
            return redirect(url_for("channel.thread", board_name=board, thread_id=new_id))
        
        return redirect(url_for("channel.board", board_name=board))
    
    return redirect(url_for("channel.thread", board_name=board, thread_id=parent))
