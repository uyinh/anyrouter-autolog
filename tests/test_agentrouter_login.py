from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from checkin import check_in_account, login_with_credentials
from utils.browser import BrowserLoginResult
from utils.config import AccountConfig, AppConfig


@pytest.mark.asyncio
@pytest.mark.parametrize(
	('fresh_login', 'user_verified', 'expected_success'),
	[(True, True, True), (True, False, False), (False, True, False)],
)
async def test_agentrouter_requires_fresh_login_and_verified_user(fresh_login, user_verified, expected_success):
	account = AccountConfig(
		cookies={}, provider='agentrouter', name='test', email='test@example.com', password='test-password'
	)
	config = AppConfig.load_from_env()
	login_result = BrowserLoginResult(cookies={'session': 'test-session'}, api_user='123', fresh_login=fresh_login)
	user_info = {'success': True, 'quota': 100.0, 'used_quota': 20.0, 'display': '余额：$100.0'}
	if not user_verified:
		user_info = {'success': False, 'error': 'HTTP 401'}

	with (
		patch('checkin.login_with_credentials', new_callable=AsyncMock, return_value=login_result),
		patch('checkin.get_user_info', return_value=user_info),
		patch('checkin.get_proxy_server', return_value=None),
		patch('checkin.httpx.Client') as client_class,
	):
		success, _, _ = await check_in_account(account, 0, config)

	assert success is expected_success
	client = client_class.return_value.__enter__.return_value
	client.cookies.update.assert_called_once_with({'session': 'test-session'})


@pytest.mark.asyncio
@pytest.mark.parametrize('already_logged_in', [False, True])
async def test_browser_records_whether_email_login_was_performed(already_logged_in):
	context = MagicMock()
	context.new_page = AsyncMock(return_value=MagicMock())
	context.cookies = AsyncMock(return_value=[{'name': 'session', 'value': 'test-session'}])
	context.close = AsyncMock()
	provider = AppConfig.load_from_env().get_provider('agentrouter')

	with (
		patch('checkin.launch_login_context', new_callable=AsyncMock, return_value=context),
		patch('checkin.prepare_browser_page', new_callable=AsyncMock),
		patch('checkin.navigate_login_page', new_callable=AsyncMock),
		patch('checkin.is_logged_in', new_callable=AsyncMock, return_value=already_logged_in),
		patch('checkin.has_session_cookie', new_callable=AsyncMock, return_value=False),
		patch('checkin.save_login_screenshot', new_callable=AsyncMock),
		patch('checkin.login_with_email_form', new_callable=AsyncMock) as email_login,
		patch('checkin.verify_browser_login', new_callable=AsyncMock, return_value={'id': 123}),
	):
		result = await login_with_credentials('test', provider, 'agentrouter', 'test@example.com', 'test-password')

	assert result is not None
	assert result.fresh_login is (not already_logged_in)
	assert email_login.await_count == (0 if already_logged_in else 1)
	context.close.assert_awaited_once()
