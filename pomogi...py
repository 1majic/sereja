import asyncio
from telethon import TelegramClient
from hashlib import sha1, sha256, pbkdf2_hmac as pbkdf2
from telethon.tl.functions.channels import GetChannelsRequest, CheckUsernameRequest, UpdateUsernameRequest, EditCreatorRequest
from telethon.tl.functions.channels import EditAdminRequest
from telethon.tl.types import ChatAdminRights, TypeInputCheckPasswordSRP
from telethon.tl.types import PeerUser, PeerChat, PeerChannel, InputCheckPasswordSRP
from telethon import functions, types
from secrets import token_bytes
import telethon.password as pwd_mod

from config import *

client = TelegramClient('anon', API_ID, API_HASH)

with TelegramClient('anon', API_ID, API_HASH) as client:
    rights = ChatAdminRights(
        change_info = True,
        post_messages = True,
        edit_messages = True,
        delete_messages = True,
        ban_users = True,
        invite_users = True,
        pin_messages = True,
        add_admins = True,
        anonymous = True,
        manage_call = True,
        other = True
    )

    channel = -1001543705731
    user = 1732801471

    # asyncio.run(test())
    async def main():
        result = await client(functions.account.GetPasswordRequest())

        password_str = "Password12345"
        
        password = pwd_mod.compute_check(result, password_str)

        await client(EditCreatorRequest(channel=channel, user_id=user, password=password))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
