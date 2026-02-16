from aiogram import Bot, Dispatcher, Router, types
from aiogram.filters import Command
from tools import Tools
import asyncio

from config import token

bot = Bot(token=token)
router = Router()
tools = Tools()

##start
@router.message(Command("start"))
async def start(message: types.Message):
    await message.answer("Hello, please send HOST to lookup and send information. Bot also support inline queries.")

@router.message(Command("s"))
async def stats(message: types.Message):
    await message.answer('Currently queries using bot: ' + str(await tools.readquery()))
##

@router.message()
async def text(message: types.Message):
    if await tools.isHost(message.text):
        await message.answer(await tools.whois(message.text))
    else:
        await message.answer('Please enter a valid host.')


@router.inline_query()
async def textquery(query: types.InlineQuery):
    text = query.query.strip()
    if await tools.isHost(text):
        result = await tools.whois(text)
        results = [
            types.InlineQueryResultArticle(
                id='1',
                title='Whois',
                input_message_content=types.InputTextMessageContent(
                    message_text=str(result)
                ),
                description=str(result)
            )
        ]
        await query.answer(results, cache_time=1)
    else:
        await query.answer('Something wrong, maybe wrong host.', cache_time=1)


async def main():
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == '__main__':
    asyncio.run(main())