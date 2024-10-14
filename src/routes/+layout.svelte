<script>
	import { navigating } from '$app/stores';
	import NProgress from 'nprogress';

	import '../app.css';
	import '../reset.css';

	NProgress.configure({
		minimum: 0.16
	});

	$: {
		if ($navigating) {
			NProgress.start();
		} else NProgress.done();
	}
</script>

<slot></slot>
