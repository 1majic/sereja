import asyncio
from telethon import TelegramClient
from hashlib import sha1, sha256, pbkdf2_hmac as pbkdf2
from telethon.tl.functions.channels import GetChannelsRequest, CheckUsernameRequest, UpdateUsernameRequest, EditCreatorRequest
from telethon.tl.functions.channels import EditAdminRequest
from telethon.tl.types import ChatAdminRights, TypeInputCheckPasswordSRP
from telethon.tl.types import PeerUser, PeerChat, PeerChannel, InputCheckPasswordSRP
from telethon import functions, types
from secrets import token_bytes

from config import *


def itb(x: int) -> bytes:
    return x.to_bytes(x.bit_length(), 'big')
    
def ifb(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


def getSRPParams(g, p, salt1, salt2, gB, password):
    def H(x):
        return sha256(x).digest()

    def SH(data, salt):
        return sha256(salt + data + salt).digest()

    def PH1(password, salt1, salt2):
        return SH(SH(password, salt1), salt2)

    def PH2(password, salt1, salt2):
        return SH(pbkdf2(hash_name='sha512', password=PH1(password, salt1, salt2), salt=salt1, iterations=100000), salt2)

    p = ifb(p)
    k = ifb(H(itb(p) + itb(g)))

    a = ifb(token_bytes(2048))

    g_a = pow(g, a, mod=p)

    u = ifb(H(itb(g_a) + itb(gB)))
    x = ifb(PH2(password.encode(), salt1, salt2))
    v = pow(g, x, mod=p)

    k_v = (k * v % p)
    g_b = (k_v + pow(g, gB, mod=p)) % p
    t = (g_b - k_v) % p
    if t < 0:
        t += p
    s_a = pow(t, a + u * x, mod=p)
    k_a = ifb(H(itb(s_a)))

    M1 = H(itb(ifb(H(itb(p))) ^ ifb(H(itb(g)))) + H(salt1) + H(salt2) + itb(g_a) + itb(g_b) + itb(k_a))

    return itb(g_a), M1


def get_srp_params(g, p, salt1, salt2, gB, password):
    def H(x):
        return sha256(x).digest()

    def SH(data, salt):
        return sha256(itb(ifb(salt) + ifb(data) + ifb(salt))).digest()

    def PH1(password, salt1, salt2):
        return SH(SH(password, salt1), salt2)

    def PH2(password, salt1, salt2):
        return SH(pbkdf2(hash_name='sha256', password=PH1(password, salt1, salt2), salt=salt1, iterations=100000), salt2)

    gInt = g

    gBytes = itb(g)

    pInt = ifb(p)

    aInt = ifb(token_bytes(256))

    gAInt = pow(gInt, aInt, mod=pInt)

    gABytes = itb(gAInt)

    gBBytes = itb(gB)

    k = H(itb(ifb(p) + ifb(gBytes)))
    u = H(itb(ifb(gABytes) + ifb(gBBytes)))
    x = PH2(password, salt1, salt2)

    kInt = ifb(k)
    uInt = ifb(u)
    xInt = ifb(x)
    vInt = pow(gInt, xInt, mod=pInt)
    kVInt = (kInt * vInt) % pInt
    tInt = (ifb(gBBytes) - kVInt) % pInt

    sAInt = pow(tInt, aInt + uInt * xInt, mod=pInt)

    sABytes = itb(sAInt)
    kA = H(sABytes)
    M1 = H(itb(ifb(H(p)) ^ ifb(H(gBytes)) + ifb(H(salt1)) + ifb(H(salt2)) + ifb(gABytes) + ifb(gBBytes) + ifb(kA)))

    return gABytes, M1


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

        g = result.current_algo.g
        p = result.current_algo.p

        password = "Password12345"
        
        salt1 = result.current_algo.salt1
        salt2 = result.current_algo.salt2

        srp_id = result.srp_id
        srp_b = ifb(result.srp_B)

        A, M1 = getSRPParams(g=g, p=p, salt1=salt1, salt2=salt2, gB=srp_b, password=password)

        password =  InputCheckPasswordSRP(srp_id=srp_id, A=A, M1=M1)

        await client(EditCreatorRequest(channel=channel, user_id=user, password=password))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
