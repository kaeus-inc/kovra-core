// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import remarkGfm from 'remark-gfm';

// kovra documentation site — kovra.sh/docs (KOV-52).
// Stack: Astro Starlight → Cloudflare Pages. Content is authored fresh and
// public-safe; every claim is validated against the actual CLI/MCP/providers
// (the private docs/ tree is Confidential and is NOT a source).
//
// NOTE (KOV-50 integration): kovra.sh root = landing (sells), kovra.sh/docs =
// these docs. Routing for the /docs split lands with the landing page (KOV-50);
// for now Starlight serves at the site root during iteration.

// Expressive Code plugin: in a terminal transcript (command + dimmed output in
// one box), the "Copy" button must copy ONLY the command — not the program's
// output. Command lines are the ones that start with a shell prompt (`~/dir % `
// for zsh, `PS …> ` for PowerShell); we recompute the copy payload from just
// those, stripped of the prompt. Blocks with no prompt line are left untouched
// (a plain snippet still copies whole). EC stores the copy text in the button's
// `data-code`, newline-separated by the DEL char (\x7F).
const PROMPT = /^(?:~[^%]*%|PS [^>]*>)\s+/;
function copyCommandOnly() {
	const setDataCode = (node, value) => {
		if (!node || typeof node !== 'object') return false;
		if (
			node.tagName === 'button' &&
			node.properties &&
			('dataCode' in node.properties || 'data-code' in node.properties)
		) {
			if ('dataCode' in node.properties) node.properties.dataCode = value;
			else node.properties['data-code'] = value;
			return true;
		}
		if (Array.isArray(node.children)) {
			for (const child of node.children) if (setDataCode(child, value)) return true;
		}
		return false;
	};
	return {
		name: 'copy-command-only',
		hooks: {
			postprocessRenderedBlock: (context) => {
				const cmds = context.codeBlock
					.getLines()
					.map((l) => l.text)
					.filter((t) => PROMPT.test(t))
					.map((t) => t.replace(PROMPT, ''));
				if (!cmds.length) return;
				setDataCode(context.renderData.blockAst, cmds.join('\x7F'));
			},
		},
	};
}

// https://astro.build/config
export default defineConfig({
	site: 'https://kovra.sh',
	// GFM (tables, strikethrough, autolinks) ships with Astro for .md but is NOT
	// applied to .mdx by default — adding it here makes tables render in BOTH, so
	// table-bearing pages can use the MDX-only <Tabs> OS selector without the
	// literal-pipes regression.
	markdown: {
		remarkPlugins: [remarkGfm],
	},
	integrations: [
		starlight({
			expressiveCode: {
				plugins: [copyCommandOnly()],
			},
			title: 'kovra',
			description:
				'Local secrets manager for development — let your tools and AI agents use your secrets without ever seeing them.',
			logo: {
				src: './src/assets/kovra-icon.png',
				alt: 'kovra',
			},
			// Fonts are vendored locally via Fontsource (no runtime CDN — brand.md
			// offline constraint). Astro bundles the woff2 into the build and serves
			// them from kovra.sh. Sora = display/wordmark, Inter = body/UI.
			customCss: [
				'@fontsource-variable/inter/wght.css',
				'@fontsource-variable/sora/wght.css',
				'./src/styles/brand.css',
			],
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/kaeus-inc/kovra-core',
				},
			],
			// Wired incrementally — each entry points to a page that already exists,
			// so `astro build` stays green at every step. Planned (not yet wired):
			// Security model, CLI reference, MCP guide, Providers, Typed
			// credentials, Sharing, Web UI, Troubleshooting.
			sidebar: [
				{
					label: 'Start here',
					items: [
						{ label: 'Introduction', slug: 'index' },
						{ label: 'Installation', slug: 'start/installation' },
						{ label: 'Quick start', slug: 'start/quick-start' },
						{ label: 'Tutorial', slug: 'start/tutorial' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Overview', slug: 'concepts' },
						{ label: 'How it works', slug: 'concepts/how-it-works' },
						{ label: 'The vault', slug: 'concepts/vault' },
						{ label: 'Coordinates', slug: 'concepts/coordinates' },
						{ label: 'Sensitivity tiers', slug: 'concepts/sensitivity' },
						{ label: 'Agent scope', slug: 'concepts/agent-scope' },
						{ label: 'The .env.refs contract', slug: 'concepts/env-refs' },
					],
				},
				{
					label: 'For AI Agents',
					items: [
						{ label: 'kovra over MCP', slug: 'agents/mcp' },
						{ label: 'MCP tool reference', slug: 'agents/tools' },
					],
				},
				{
					label: 'Credentials & providers',
					items: [
						{ label: 'TOTP codes', slug: 'guides/totp' },
						{ label: 'Keypairs & signing', slug: 'guides/keypairs' },
						{ label: 'Governed ssh-agent', slug: 'guides/ssh-agent' },
						{ label: 'Cloud references', slug: 'guides/references' },
						{ label: 'Import from 1Password', slug: 'guides/import' },
					],
				},
				{
					label: 'Sharing',
					items: [
						{ label: 'Sealed packages', slug: 'guides/sharing' },
						{ label: 'USB exchange', slug: 'guides/usb-exchange' },
					],
				},
				{ label: 'The Web UI', slug: 'guides/web-ui' },
				{
					label: 'Operations',
					items: [
						{ label: 'Headless & CI', slug: 'operations/headless-ci' },
						{ label: 'Git hooks', slug: 'operations/git-hooks' },
						{ label: 'The audit trail', slug: 'operations/audit' },
						{ label: 'Backup & recovery', slug: 'operations/backup-recovery' },
						{ label: 'Attended confirmation', slug: 'operations/attended-confirmation' },
					],
				},
				{
					label: 'Security model',
					items: [
						{ label: 'Secrets in the age of AI Agents', slug: 'security/rationale' },
						{ label: 'The decision process', slug: 'security/decision' },
						{ label: 'Cryptography', slug: 'security/cryptography' },
						{ label: 'Threat model', slug: 'security/threat-model' },
						{ label: 'Flows', slug: 'security/flows' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI reference', slug: 'reference/cli' },
						{ label: 'Configuration', slug: 'reference/configuration' },
						{ label: 'Troubleshooting', slug: 'reference/troubleshooting' },
						{ label: 'FAQ', slug: 'reference/faq' },
						{ label: 'Glossary', slug: 'reference/glossary' },
					],
				},
				{
					label: 'Project',
					items: [
						{ label: 'License', slug: 'project/license' },
						{ label: 'Contributing', slug: 'project/contributing' },
						{ label: 'Support & community', slug: 'project/support' },
					],
				},
			],
		}),
	],
});
