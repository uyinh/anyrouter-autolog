#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import random
import re
import sys
from datetime import datetime, timedelta, timezone

if hasattr(sys.stdout, 'reconfigure'):
	sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
	sys.stderr.reconfigure(line_buffering=True)

import httpx
from cloakbrowser import launch_async
from dotenv import load_dotenv

from utils.browser import (
	BrowserLoginResult,
	has_session_cookie,
	is_logged_in,
	launch_login_context,
	load_browser_login_settings,
	login_with_email_form,
	navigate_login_page,
	prepare_browser_page,
	save_login_screenshot,
	take_pending_screenshots,
	verify_browser_login,
	wait_for_waf_ready,
)
from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.debug import debug_print, is_debug_enabled
from utils.headers import get_browser_headers
from utils.notify import notify
from utils.oauth_agentrouter import AgentRouterOAuthClient
from utils.proxy import get_playwright_proxy, get_proxy_server

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = (
		{k: {'quota': v.get('quota'), 'used': v.get('used')} for k, v in balances.items()} if balances else {}
	)
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_browser(
	account_name: str,
	login_url: str,
	required_cookies: list[str],
	*,
	use_proxy: bool = False,
):
	"""使用浏览器获取 WAF cookies"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	launch_kwargs: dict = {'headless': True}
	proxy = get_playwright_proxy(use_proxy=use_proxy)
	if proxy:
		launch_kwargs['proxy'] = proxy
	browser = await launch_async(**launch_kwargs)

	try:
		page = await browser.new_page()
		await prepare_browser_page(page)
		print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

		await page.goto(login_url, wait_until='domcontentloaded')
		await wait_for_waf_ready(page)

		cookies = await page.context.cookies()

		waf_cookies = {}
		for cookie in cookies:
			cookie_name = cookie.get('name')
			cookie_value = cookie.get('value')
			if cookie_name in required_cookies and cookie_value is not None:
				waf_cookies[cookie_name] = cookie_value

		print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

		missing_cookies = [c for c in required_cookies if c not in waf_cookies]

		if missing_cookies:
			print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
			await browser.close()
			return None

		print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')
		await browser.close()
		return waf_cookies

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
		await browser.close()
		return None


async def login_with_credentials(
	account_name: str,
	provider_config,
	provider_name: str,
	email: str,
	password: str,
) -> BrowserLoginResult | None:
	"""使用邮箱密码通过浏览器登录，返回 cookies 与拦截到的 api user id。"""
	print(f'[PROCESSING] {account_name}: Logging in with email/password...')

	login_url = f'{provider_config.domain}{provider_config.login_path}'
	settings = load_browser_login_settings(
		account_name,
		provider_name,
		persist_profile=provider_config.persist_profile,
	)
	timeout_ms = settings.wait_timeout_ms

	debug_print(
		f'[INFO] {account_name}: Browser profile={settings.profile_dir}, '
		f'persist={settings.persist_profile}, headless={settings.headless}, '
		f'humanize={settings.humanize}, timeout={timeout_ms}ms'
	)

	print(
		f'[INFO] {account_name}: Provider proxy={"enabled" if provider_config.use_proxy else "disabled"} '
		f'({provider_name})'
	)

	try:
		context = await launch_login_context(settings, use_proxy=provider_config.use_proxy)
	except Exception as e:
		print(f'[FAILED] {account_name}: Browser launch failed: {e}')
		return BrowserLoginResult(cookies={}, error='浏览器启动失败')

	page = None
	try:
		page = await context.new_page()
		await prepare_browser_page(page)
		await navigate_login_page(
			page,
			login_url,
			timeout_ms,
			provider=provider_name,
			account_name=account_name,
		)

		fresh_login = False
		if not await is_logged_in(page):
			if await has_session_cookie(page):
				print(f'[WARN] {account_name}: Stale session cookie on login page, forcing email login')
			await save_login_screenshot(page, provider_name, account_name, 'before-email-login')
			await login_with_email_form(
				page,
				email,
				password,
				timeout_ms,
				provider=provider_name,
				account_name=account_name,
			)
			fresh_login = True
		else:
			print(f'[INFO] {account_name}: Browser profile already logged in')

		console_url = f'{provider_config.domain}/console'
		user_profile = await verify_browser_login(page, console_url, timeout_ms)
		if not user_profile:
			cookies = await context.cookies()
			cookie_names = [c.get('name') for c in cookies if c.get('name')]
			print(f'[FAILED] {account_name}: Login failed - /api/user/self not verified')
			debug_print(f'[INFO] {account_name}: Current URL: {page.url}')
			debug_print(f'[INFO] {account_name}: Got cookies: {cookie_names}')
			await save_login_screenshot(page, provider_name, account_name, 'not-authenticated')
			await context.close()
			return BrowserLoginResult(cookies={}, error='登录后用户信息校验未通过')

		cookies = await context.cookies()
		all_cookies = {
			cookie['name']: cookie['value'] for cookie in cookies if cookie.get('name') and cookie.get('value')
		}
		api_user = str(user_profile['id']) if user_profile.get('id') is not None else None

		success_msg = f'[SUCCESS] {account_name}: Login successful, got {len(all_cookies)} cookies'
		if is_debug_enabled() and api_user:
			success_msg += f', api_user={api_user}'
		print(success_msg)
		await context.close()
		return BrowserLoginResult(cookies=all_cookies, api_user=api_user, fresh_login=fresh_login)

	except Exception as e:
		error = summarize_failure_reason(e, sensitive_values=(email, password))
		print(f'[FAILED] {account_name}: {error}')
		if page is not None:
			await save_login_screenshot(page, provider_name, account_name, 'login-error')
		await context.close()
		return BrowserLoginResult(cookies={}, error=error)


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
			return {'success': False, 'error': data.get('message') or '用户信息请求被拒绝'}
		return {'success': False, 'error': f'用户信息接口返回 HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'用户信息查询失败：{summarize_failure_reason(e)}'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_browser(
			account_name,
			login_url,
			provider_config.waf_cookie_names,
			use_proxy=provider_config.use_proxy,
		)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if not isinstance(result, dict):
				return False, '签到接口响应格式异常'
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True, 'checkin_completed'
			else:
				error_msg = result.get('msg') or result.get('message') or '签到接口未说明失败原因'
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					print(f'[SUCCESS] {account_name}: Already checked in today')
					return True, 'already_checked_in'
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False, str(error_msg)
		except json.JSONDecodeError:
			return False, '签到接口返回了非 JSON 响应'
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False, f'签到接口返回 HTTP {response.status_code}'


def summarize_failure_reason(error: Exception | str, *, sensitive_values: tuple[str, ...] = ()) -> str:
	"""保留可处理的错误原因，隐藏请求地址和响应正文。"""
	message = str(error)
	for value in sensitive_values:
		if value:
			message = message.replace(value, '***')
	if 'Login page never rendered' in message:
		return '登录页面未加载完成'
	if any(text in message for text in ('Cannot find', 'Cannot open email login form')):
		return '登录表单未就绪'
	if isinstance(error, (httpx.TimeoutException, TimeoutError)) or 'Timeout' in message:
		return '请求或页面等待超时'
	if isinstance(error, httpx.TransportError) or 'net::ERR_' in message:
		return '网络连接失败'
	for provider in ('GitHub', 'LinuxDo'):
		if f'未能从 {provider} 获取授权码' in message:
			return f'{provider} 授权失败'
	message = re.sub(r'https?://\S+', '[地址]', message)
	return re.sub(r'\s+', ' ', message).strip()[:100] or '未返回失败原因'


def format_check_in_notification(detail: dict) -> str:
	"""每个账号一行，显示结果、实际额度变化和可查询余额。"""
	name = detail['name']
	after = detail['after'] or {}
	before = detail['before'] or {}
	if detail['success']:
		status = '签到成功'
	else:
		status = '登录失败' if after.get('checkin_status') == 'login_failed' else '签到失败'

	change = '增量未知'
	if before.get('success') and after.get('success'):
		quota_change = round(after['quota'] + after['used_quota'] - before['quota'] - before['used_quota'], 2) or 0
		change = f'{quota_change:+.2f}'.rstrip('0').rstrip('.')
	elif not detail['success'] or after.get('checkin_status') == 'already_checked_in':
		change = '+0'

	balance_info = after if after.get('success') else before if not detail['success'] else {}
	balance = f'{balance_info["quota"]:.2f}' if balance_info.get('success') else '未知'
	result = f'{status}，{change}'
	if detail['success'] and (change == '增量未知' or after.get('checkin_status') == 'already_checked_in'):
		result = '今日已签到'
	return f'{name}：{result} · 余额 {balance}'


def format_check_in_report(results: list[dict], execution_time: datetime | None = None) -> str:
	success_count = sum(result['success'] for result in results)
	execution_time = (execution_time or datetime.now(timezone.utc)).astimezone(timezone(timedelta(hours=8)))
	lines = [
		f'执行结果：{success_count}/{len(results)} 通过，{len(results) - success_count} 失败',
		execution_time.strftime('%Y-%m-%d %H:%M（北京时间）'),
	]
	lines.extend(format_check_in_notification(result) for result in sorted(results, key=lambda item: item['success']))
	return '\n'.join(lines)


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, {'success': False, 'error': '服务商配置不存在'}

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	# 邮箱密码优先
	all_cookies = None
	resolved_api_user: str | None = None
	fresh_login = False
	auth_method = None
	if account.has_login_credentials():
		print(f'[INFO] {account_name}: Attempting email/password login (priority)...')
		assert account.email is not None and account.password is not None
		login_result = await login_with_credentials(
			account_name,
			provider_config,
			account.provider,
			account.email,
			account.password,
		)
		if login_result and not login_result.error:
			all_cookies = login_result.cookies
			resolved_api_user = login_result.api_user
			fresh_login = login_result.fresh_login
			auth_method = 'email/password'
		else:
			print(f'[FAILED] {account_name}: Email/password login failed, will not use stale session cookies')
			error = login_result.error if login_result else '邮箱密码登录失败'
			return False, None, {'success': False, 'error': error, 'checkin_status': 'login_failed'}
	elif account.provider == 'agentrouter' and account.has_oauth_session():
		print(f'[INFO] {account_name}: Attempting OAuth silent re-login for AgentRouter...')
		user_cookies = parse_cookies(account.cookies)
		all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
		if not all_cookies:
			return False, None, {'success': False, 'error': '无法获取站点验证 Cookie', 'checkin_status': 'login_failed'}
		return await run_agentrouter_oauth_checkin(all_cookies, account, account_name, provider_config)
	else:
		user_cookies = parse_cookies(account.cookies)
		if not user_cookies:
			print(f'[FAILED] {account_name}: Invalid configuration format')
			return (
				False,
				None,
				{
					'success': False,
					'error': '账号 Cookie 配置为空或格式错误',
					'checkin_status': 'login_failed',
				},
			)
		all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
		auth_method = 'session cookies'

	if not all_cookies:
		return False, None, {'success': False, 'error': '无法获取有效登录会话', 'checkin_status': 'login_failed'}

	print(f'[AUTH] {account_name}: Using auth method -> {auth_method}')

	return run_check_in_requests(
		all_cookies,
		account,
		account_name,
		provider_config,
		api_user_override=resolved_api_user,
		use_proxy=provider_config.use_proxy,
		fresh_login=fresh_login,
	)


async def run_agentrouter_oauth_checkin(
	all_cookies: dict,
	account: AccountConfig,
	account_name: str,
	provider_config,
) -> tuple[bool, dict | None, dict | None]:
	"""通过 AgentRouter 的 OAuth 静默授权重登录流程完成真实签到。"""
	user_info_before = None
	failure_status = 'login_failed'
	try:
		proxy_url = get_proxy_server(use_proxy=provider_config.use_proxy)
		oauth_client = AgentRouterOAuthClient(domain=provider_config.domain)

		client_kwargs: dict = {'http2': True, 'timeout': 30.0}
		if proxy_url:
			client_kwargs['proxy'] = proxy_url
			if is_debug_enabled():
				print(f'[INFO] {account_name}: HTTP client proxy enabled: {proxy_url}')
			else:
				print(f'[INFO] {account_name}: HTTP client proxy enabled')
		elif provider_config.use_proxy:
			print(f'[WARN] {account_name}: Provider requires proxy but CHECKIN_PROXY_URL is not set')

		with httpx.Client(**client_kwargs) as client:
			if all_cookies:
				client.cookies.update(all_cookies)
			headers = get_browser_headers(domain=provider_config.domain)
			if account.api_user:
				headers[provider_config.api_user_key] = account.api_user

			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
			user_info_before = get_user_info(client, headers, user_info_url)
			if user_info_before and user_info_before.get('success'):
				print(user_info_before['display'])

			# 1. 获取签名 state
			state = oauth_client.fetch_oauth_state(client)

			# 2. 授权换 code
			if account.github_session:
				oauth_provider = 'github'
				code = oauth_client.authorize_github(
					account.github_session,
					state,
					proxy_url=proxy_url,
				)
			elif account.linuxdo_session:
				oauth_provider = 'linuxdo'
				code = oauth_client.authorize_linuxdo(
					account.linuxdo_session,
					state,
					proxy_url=proxy_url,
				)
			else:
				print(f'[FAILED] {account_name}: Missing OAuth session token')
				return (
					False,
					user_info_before,
					{
						'success': False,
						'error': '缺少 OAuth 会话',
						'checkin_status': 'login_failed',
					},
				)

			# 3. 回调登录发奖
			success, user_data, checked_in, msg = oauth_client.callback_login(
				client,
				provider=oauth_provider,
				code=code,
				state=state,
			)

			if not success:
				print(f'[FAILED] {account_name}: OAuth login callback failed - {msg}')
				return (
					False,
					user_info_before,
					{
						'success': False,
						'error': f'OAuth 登录失败：{msg}',
						'checkin_status': 'login_failed',
					},
				)
			failure_status = 'checkin_failed'

			uid = str(user_data.get('id') or '')
			if uid:
				headers[provider_config.api_user_key] = uid

			user_info_after = get_user_info(client, headers, user_info_url)

			if checked_in:
				print(f'[SUCCESS] {account_name}: OAuth check-in successful! Reward added to balance.')
			else:
				print(f'[INFO] {account_name}: OAuth 登录已完成')

			status = 'reward_received' if checked_in else 'login_verified'
			return True, user_info_before, {**user_info_after, 'checkin_status': status}

	except Exception as e:
		error = summarize_failure_reason(e)
		print(f'[FAILED] {account_name}: OAuth check-in error: {error}')
		return False, user_info_before, {'success': False, 'error': error, 'checkin_status': failure_status}


def run_check_in_requests(
	all_cookies: dict,
	account: AccountConfig,
	account_name: str,
	provider_config,
	*,
	api_user_override: str | None = None,
	use_proxy: bool = False,
	fresh_login: bool = False,
) -> tuple[bool, dict | None, dict | None]:
	"""执行 HTTP 签到请求（同步，避免在 async 上下文中使用阻塞 httpx）。"""
	user_info_before = None
	try:
		client_kwargs: dict = {'http2': True, 'timeout': 30.0}
		proxy_url = get_proxy_server(use_proxy=use_proxy)
		if proxy_url:
			client_kwargs['proxy'] = proxy_url
			if is_debug_enabled():
				print(f'[INFO] {account_name}: HTTP client proxy enabled: {proxy_url}')
			else:
				print(f'[INFO] {account_name}: HTTP client proxy enabled')
		elif use_proxy:
			print(f'[WARN] {account_name}: Provider requires proxy but CHECKIN_PROXY_URL is not set')

		with httpx.Client(**client_kwargs) as client:
			client.cookies.update(all_cookies)

			headers = get_browser_headers(domain=provider_config.domain)
			api_user = api_user_override or account.api_user
			if api_user:
				headers[provider_config.api_user_key] = api_user
			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
			user_info_before = get_user_info(client, headers, user_info_url)
			if user_info_before and user_info_before.get('success'):
				print(user_info_before['display'])
			elif user_info_before:
				print(user_info_before.get('error', 'Unknown error'))

			if provider_config.needs_manual_check_in():
				success, status = execute_check_in(client, account_name, provider_config, headers)
				if not success:
					return False, user_info_before, {'success': False, 'error': status}
				user_info_after = get_user_info(client, headers, user_info_url)
				return True, user_info_before, {**user_info_after, 'checkin_status': status}

			if provider_config.name == 'agentrouter':
				if fresh_login:
					if user_info_before and user_info_before.get('success'):
						print(f'[SUCCESS] {account_name}: AgentRouter 邮箱密码重新登录完成，已验证用户信息')
						return True, None, {**user_info_before, 'checkin_status': 'login_verified'}
					print(f'[FAILED] {account_name}: AgentRouter 重新登录后无法验证用户信息')
					return False, user_info_before, {**(user_info_before or {}), 'checkin_status': 'login_failed'}
				print(
					f'[WARN] {account_name}: AgentRouter 签到奖励在登录鉴权时由服务端发放（官方 FAQ：需要退出后重新登录才会到账）。'
				)
				print(f'[WARN] {account_name}: 当前仅提供了静态 Session Cookie，未触发登录事件，额度不会增长。')
				print(f'[HINT] {account_name}: 请配置邮箱密码或 OAuth 会话，并使用新的登录会话执行签到。')
				return (
					False,
					user_info_before,
					{
						'success': False,
						'error': '需要重新登录，当前复用了旧会话',
						'checkin_status': 'login_failed',
					},
				)

			user_info_after = get_user_info(client, headers, user_info_url)
			if user_info_after and user_info_after.get('success'):
				print(f'[INFO] {account_name}: 用户信息查询成功')
				return True, user_info_before, {**user_info_after, 'checkin_status': 'balance_verified'}
			error = user_info_after.get('error', 'Unknown error') if user_info_after else 'Unknown error'
			print(f'[FAILED] {account_name}: Auto check-in failed - {error}')
			return False, user_info_before, user_info_after

	except Exception as e:
		error = summarize_failure_reason(e)
		print(f'[FAILED] {account_name}: {error}')
		return False, user_info_before, {'success': False, 'error': error}


async def main():
	"""主函数"""
	if is_debug_enabled():
		print('[INFO] DEBUG_MODE enabled')
		proxy_server = os.getenv('CHECKIN_PROXY_URL', '').strip()
		if proxy_server:
			print(f'[INFO] Proxy endpoint available: {proxy_server} (enabled per provider use_proxy)')
		else:
			print('[INFO] CHECKIN_PROXY_URL not set; providers with use_proxy=true will run without proxy')
	else:
		print('[INFO] Debug mode disabled (set DEBUG_MODE=true to enable screenshots and verbose logs)')

	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')
	if is_debug_enabled():
		for provider_name, provider in sorted(app_config.providers.items()):
			print(f'[INFO] Provider "{provider_name}": use_proxy={provider.use_proxy}')

	accounts = load_accounts_config()
	if not accounts:
		error_msg = '[FAILED] Unable to load account configuration, program exits'
		print(error_msg)
		notify.push_message('AnyRouter Check-in Alert', error_msg, msg_type='text')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()
	results = []
	current_balances = {}

	for i, account in enumerate(accounts):
		if i > 0:
			jitter_secs = random.randint(5, 18)  # nosec B311：仅用于执行间隔
			print(f'[INFO] Account jitter: waiting {jitter_secs}s before next account...')
			await asyncio.sleep(jitter_secs)
		try:
			success, before, after = await check_in_account(account, i, app_config)
			error = (after or {}).get('error') or (before or {}).get('error') or '未返回失败原因'
		except Exception as exc:
			success, before, after = False, None, None
			error = summarize_failure_reason(exc)
		results.append(
			{'name': account.name or f'{i + 1}号', 'success': success, 'before': before, 'after': after, 'error': error}
		)
		if after and after.get('success'):
			current_balances[f'account_{i + 1}'] = {'quota': after['quota'], 'used': after['used_quota']}

	success_count = sum(result['success'] for result in results)
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	balance_changed = current_balance_hash is not None and current_balance_hash != last_balance_hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if success_count < len(accounts) or balance_changed:
		notify_content = format_check_in_report(results)
		screenshot_paths = take_pending_screenshots() if is_debug_enabled() else []
		if screenshot_paths:
			notify_content += f'\n调试截图：{len(screenshot_paths)} 张'
			github_run_id = os.getenv('GITHUB_RUN_ID', '').strip()
			github_repo = os.getenv('GITHUB_REPOSITORY', '').strip()
			if github_run_id and github_repo:
				notify_content += f'\nhttps://github.com/{github_repo}/actions/runs/{github_run_id}'
		print(notify_content)
		notify.push_message('AnyRouter 执行结果', notify_content, msg_type='text')
	else:
		print(f'[INFO] {success_count}/{len(accounts)} 个账号处理通过，余额无变化，跳过通知')

	sys.exit(0 if success_count == len(accounts) else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
