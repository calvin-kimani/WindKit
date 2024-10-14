import PocketBase, { getTokenPayload } from 'pocketbase';

/** @type {import('@sveltejs/kit').Handle} */
export async function handle({ event, resolve }) {
	const { cookies } = event;

	event.locals.pb = new PocketBase(import.meta.env.VITE_PB_URL);

	// Load the store data from the request cookie string
	event.locals.pb.authStore.loadFromCookie(event.request.headers.get('cookie') || '');

	try {
		if (event.locals.pb.authStore.isValid) {
			await event.locals.pb.collection('users').authRefresh();
		}
	} catch (err) {
		console.error('Failed to refresh auth:', err);
		event.locals.pb.authStore.clear();
	}

	const response = await resolve(event);

	// Manage the auth cookie
	const { token } = event.locals.pb.authStore;
	const payload = token ? getTokenPayload(token) : null;
	const secureFlag = event.url.protocol === 'https:' ? 'Secure; ' : '';

	if (payload) {
		const cookieValue = JSON.stringify({ token });
		const expires = new Date(payload.exp * 1000).toUTCString();

		response.headers.append(
			'set-cookie',
			`pb_auth=${cookieValue}; Path=/; Expires=${expires}; ${secureFlag}HttpOnly; SameSite=Strict`
		);
	} else {
		// If no token, clear the cookie
		response.headers.append(
			'set-cookie',
			`pb_auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ${secureFlag}HttpOnly; SameSite=Strict`
		);
	}

	return response;
}
