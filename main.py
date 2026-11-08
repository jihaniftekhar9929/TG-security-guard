import os
import re
import sqlite3
import logging
from datetime import datetime, timezone

from telegram import Update, ChatPermissions
from telegram.constants import ChatMemberStatus
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ChatMemberHandler,
    ContextTypes,
    filters,
)

# ---------------- CONFIG ----------------

TOKEN = os.environ["BOT_TOKEN"]
OWNER_ID = int(os.environ["OWNER_ID"])
BLOCK_LINKS = os.getenv("BLOCK_LINKS", "true").lower() == "true"
DB_PATH = os.getenv("DB_PATH", "security.db")

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# ---------------- DATABASE ----------------

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    last_seen TEXT
)
""")
db.execute("""
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER,
    user_id INTEGER,
    event TEXT,
    created_at TEXT
)
""")
db.commit()


def now():
    return datetime.now(timezone.utc).isoformat()


def save_user(user):
    if not user or user.is_bot:
        return

    db.execute("""
    INSERT INTO users
    (user_id, username, first_name, last_name, last_seen)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
    username=excluded.username,
    first_name=excluded.first_name,
    last_name=excluded.last_name,
    last_seen=excluded.last_seen
    """, (
        user.id,
        user.username,
        user.first_name,
        user.last_name,
        now()
    ))
    db.commit()


def log_event(chat_id, user_id, event):
    db.execute("""
    INSERT INTO events (chat_id, user_id, event, created_at)
    VALUES (?, ?, ?, ?)
    """, (chat_id, user_id, event, now()))
    db.commit()


# ---------------- PERMISSIONS ----------------

async def is_admin(update, context):
    chat = update.effective_chat
    user = update.effective_user

    if not chat or not user:
        return False

    if user.id == OWNER_ID:
        return True

    try:
        member = await context.bot.get_chat_member(
            chat.id, user.id
        )
        return member.status in (
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER
        )
    except Exception:
        return False


async def is_target_admin(chat, bot, user_id):
    try:
        member = await bot.get_chat_member(chat.id, user_id)
        return member.status in (
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER
        )
    except Exception:
        return False


async def get_target(update, context):
    msg = update.effective_message

    if msg.reply_to_message:
        return msg.reply_to_message.from_user

    if context.args:
        value = context.args[0]

        if value.isdigit():
            user_id = int(value)
            row = db.execute(
                "SELECT user_id, username, first_name, last_name "
                "FROM users WHERE user_id=?",
                (user_id,)
            ).fetchone()

        elif value.startswith("@"):
            row = db.execute(
                "SELECT user_id, username, first_name, last_name "
                "FROM users WHERE LOWER(username)=LOWER(?)",
                (value[1:],)
            ).fetchone()
        else:
            return None

        if row:
            from telegram import User
            return User(
                id=row[0],
                first_name=row[2] or "Unknown",
                last_name=row[3],
                username=row[1],
                is_bot=False
            )

    return None


# ---------------- START ----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡 Welcome to TG Security Guard!\n\n"
        "আমি তোমার গ্রুপের নিরাপত্তা পর্যবেক্ষণ করতে সাহায্য করব।\n\n"
        "Commands:\n"
        "/id - User ID\n"
        "/info - User information\n"
        "/stats - Group statistics\n"
        "/logs - Security logs\n"
        "/help - Help"
    )


async def help_command(update, context):
    await update.message.reply_text(
        "🛡 SECURITY BOT HELP\n\n"
        "/id - ID দেখুন\n"
        "/info - User information\n"
        "/ban - Reply করে ব্যান\n"
        "/unban USER_ID - Unban\n"
        "/mute - Reply করে mute\n"
        "/unmute USER_ID - Unmute\n"
        "/stats - Group statistics\n"
        "/logs - Recent security logs\n\n"
        "Moderation commands শুধু গ্রুপ অ্যাডমিন ব্যবহার করতে পারবেন।"
    )


# ---------------- USER INFORMATION ----------------

async def id_command(update, context):
    user = await get_target(update, context)
    user = user or update.effective_user

    if not user:
        return

    save_user(user)

    await update.message.reply_text(
        f"🆔 Telegram User ID: {user.id}\n"
        f"Username: @{user.username or 'Not available'}"
    )


async def info_command(update, context):
    user = await get_target(update, context)
    user = user or update.effective_user

    if not user:
        await update.message.reply_text(
            "User পাওয়া যায়নি। Reply করে /info দিন "
            "অথবা আগে থেকে পরিচিত @username দিন।"
        )
        return

    save_user(user)

    row = db.execute(
        "SELECT last_seen FROM users WHERE user_id=?",
        (user.id,)
    ).fetchone()

    result = (
        "👤 USER INFORMATION\n\n"
        f"Name: {user.full_name}\n"
        f"Username: @{user.username or 'None'}\n"
        f"User ID: {user.id}\n"
        f"Bot Account: {'Yes' if user.is_bot else 'No'}\n"
        f"Last observed: {row[0] if row else 'Unknown'}\n\n"
        "Note: Telegram account creation date এবং "
        "অন্য গ্রুপ/চ্যানেলের সদস্যতালিকা Bot API প্রকাশ করে না।"
    )

    if update.effective_chat.type != "private":
        if await context.bot.get_chat_member(
            update.effective_chat.id, user.id
        ):
            result += "\nGroup membership: Status checked"

    await update.message.reply_text(result)


# ---------------- JOIN / LEAVE TRACKING ----------------

async def new_members(update, context):
    message = update.effective_message
    for user in message.new_chat_members:
        save_user(user)
        log_event(message.chat_id, user.id, "JOIN")

        await message.reply_text(
            f"👋 Welcome {user.mention_html()}!\n"
            f"🆔 ID: {user.id}",
            parse_mode="HTML"
        )


async def member_updates(update, context):
    change = update.chat_member
    if not change:
        return

    user = change.new_chat_member.user
    save_user(user)

    old = change.old_chat_member.status
    new = change.new_chat_member.status

    if new in ("member", "administrator", "creator"):
        if old in ("left", "kicked"):
            log_event(change.chat.id, user.id, "JOIN")

    elif new in ("left", "kicked"):
        log_event(change.chat.id, user.id, "LEAVE")


# ---------------- MESSAGE SECURITY ----------------

LINK_PATTERN = re.compile(
    r"(https?://|www\.|t\.me/)",
    re.IGNORECASE
)

async def check_message(update, context):
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not msg or not user or user.is_bot:
        return

    save_user(user)

    if chat.type == "private":
        return

    # Admin messages are not moderated
    if await is_target_admin(chat, context.bot, user.id):
        return

    text = msg.text or msg.caption or ""

    entities = list(msg.entities or []) + list(
        msg.caption_entities or []
    )

    has_link = bool(LINK_PATTERN.search(text)) or any(
        entity.type in ("url", "text_link")
        for entity in entities
    )

    if BLOCK_LINKS and has_link:
        try:
            await msg.delete()
            log_event(chat.id, user.id, "LINK_DELETED")
            await context.bot.send_message(
                chat.id,
                f"⚠️ {user.first_name}, Links are not allowed."
            )
        except Exception as e:
            logging.warning("Delete failed: %s", e)


# ---------------- MODERATION ----------------

async def ban_command(update, context):
    if not await is_admin(update, context):
        return

    user = await get_target(update, context)
    if not user:
        await update.message.reply_text(
            "যে সদস্যকে ব্যান করবে তার মেসেজে Reply করে /ban দাও।"
        )
        return

    chat = update.effective_chat

    if await is_target_admin(chat, context.bot, user.id):
        await update.message.reply_text("Admin-কে ব্যান করা যাবে না।")
        return

    try:
        await context.bot.ban_chat_member(chat.id, user.id)
        log_event(chat.id, user.id, "BANNED")
        await update.message.reply_text(
            f"🚫 {user.first_name} banned."
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


async def unban_command(update, context):
    if not await is_admin(update, context):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text(
            "ব্যবহার: /unban USER_ID"
        )
        return

    uid = int(context.args[0])

    try:
        await context.bot.unban_chat_member(
            update.effective_chat.id, uid
        )
        log_event(update.effective_chat.id, uid, "UNBANNED")
        await update.message.reply_text("✅ Unbanned.")
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


async def mute_command(update, context):
    if not await is_admin(update, context):
        return

    user = await get_target(update, context)
    if not user:
        await update.message.reply_text(
            "সদস্যের মেসেজে Reply করে /mute দাও।"
        )
        return

    chat = update.effective_chat

    if await is_target_admin(chat, context.bot, user.id):
        await update.message.reply_text("Admin-কে mute করা যাবে না।")
        return

    try:
        await context.bot.restrict_chat_member(
            chat.id,
            user.id,
            permissions=ChatPermissions(can_send_messages=False)
        )
        log_event(chat.id, user.id, "MUTED")
        await update.message.reply_text(
            f"🔇 {user.first_name} muted."
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


async def unmute_command(update, context):
    if not await is_admin(update, context):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text(
            "ব্যবহার: /unmute USER_ID"
        )
        return

    uid = int(context.args[0])

    try:
        await context.bot.restrict_chat_member(
            update.effective_chat.id,
            uid,
            permissions=ChatPermissions(can_send_messages=True)
        )
        log_event(update.effective_chat.id, uid, "UNMUTED")
        await update.message.reply_text("🔊 Unmuted.")
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


# ---------------- STATISTICS / LOGS ----------------

async def stats_command(update, context):
    chat = update.effective_chat

    count = db.execute(
        "SELECT COUNT(DISTINCT user_id) FROM events WHERE chat_id=?",
        (chat.id,)
    ).fetchone()[0]

    joins = db.execute(
        "SELECT COUNT(*) FROM events WHERE chat_id=? AND event='JOIN'",
        (chat.id,)
    ).fetchone()[0]

    leaves = db.execute(
        "SELECT COUNT(*) FROM events WHERE chat_id=? AND event='LEAVE'",
        (chat.id,)
    ).fetchone()[0]

    await update.message.reply_text(
        f"📊 SECURITY STATISTICS\n\n"
        f"Tracked users: {count}\n"
        f"Join events: {joins}\n"
        f"Leave events: {leaves}"
    )


async def logs_command(update, context):
    if not await is_admin(update, context):
        return

    chat = update.effective_chat

    rows = db.execute(
        "SELECT user_id, event, created_at FROM events "
        "WHERE chat_id=? ORDER BY id DESC LIMIT 10",
        (chat.id,)
    ).fetchall()

    if not rows:
        await update.message.reply_text("কোনো লগ পাওয়া যায়নি।")
        return

    output = "📋 RECENT SECURITY LOGS\n\n"

    for uid, event, created in rows:
        output += f"ID: {uid} | {event}\n{created}\n\n"

    await update.message.reply_text(output)


# ---------------- RUN BOT ----------------

def main():
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("id", id_command))
    app.add_handler(CommandHandler("info", info_command))
    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("unban", unban_command))
    app.add_handler(CommandHandler("mute", mute_command))
    app.add_handler(CommandHandler("unmute", unmute_command))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("logs", logs_command))

    app.add_handler(
        MessageHandler(
            filters.StatusUpdate.NEW_CHAT_MEMBERS,
            new_members
        )
    )

    app.add_handler(
        ChatMemberHandler(
            member_updates,
            ChatMemberHandler.CHAT_MEMBER
        )
    )

    app.add_handler(
        MessageHandler(
            filters.ALL & ~filters.COMMAND,
            check_message
        )
    )

    logging.info("TG Security Guard started!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
