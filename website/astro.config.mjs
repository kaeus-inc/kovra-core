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
				// Brand favicon — the kovra cobra head from the brand sheet
				// (docs/design/kovra-brand-sheet.jpeg), not Starlight's default sparkle.
				favicon: '/favicon.png',
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
			// Bilingual: English at the root, Spanish under /es/. Untranslated
			// pages fall back to English with a notice (Starlight default).
			locales: {
				root: { label: 'English', lang: 'en' },
				es: { label: 'Español', lang: 'es' },
			},
			// Wired incrementally — each entry points to a page that already exists,
			// so `astro build` stays green at every step. Planned (not yet wired):
			// Security model, CLI reference, MCP guide, Providers, Typed
			// credentials, Sharing, Web UI, Troubleshooting.
			sidebar: [
				{
					label: 'Start here',
					translations: { es: 'Empieza aquí' },
					items: [
						{ label: 'Introduction', translations: { es: 'Introducción' }, slug: 'index' },
						{ label: 'Installation', translations: { es: 'Instalación' }, slug: 'start/installation' },
						{ label: 'Quick start', translations: { es: 'Inicio rápido' }, slug: 'start/quick-start' },
						{ label: 'Tutorial', translations: { es: 'Tutorial' }, slug: 'start/tutorial' },
					],
				},
				{ label: 'Vision, mission & values', translations: { es: 'Visión, misión y valores' }, slug: 'about/vision' },
				{
					label: 'Concepts',
					translations: { es: 'Conceptos' },
					items: [
						{ label: 'Overview', translations: { es: 'Vista general' }, slug: 'concepts' },
						{ label: 'How it works', translations: { es: 'Cómo funciona' }, slug: 'concepts/how-it-works' },
						{ label: 'The vault', translations: { es: 'La bóveda' }, slug: 'concepts/vault' },
						{ label: 'Coordinates', translations: { es: 'Coordenadas' }, slug: 'concepts/coordinates' },
						{ label: 'Sensitivity tiers', translations: { es: 'Niveles de sensibilidad' }, slug: 'concepts/sensitivity' },
						{ label: 'Agent scope', translations: { es: 'Alcance del agente' }, slug: 'concepts/agent-scope' },
						{ label: 'The .env.refs contract', translations: { es: 'El contrato .env.refs' }, slug: 'concepts/env-refs' },
					],
				},
				{
					label: 'For AI Agents',
					translations: { es: 'Para agentes de IA' },
					items: [
						{ label: 'kovra over MCP', translations: { es: 'kovra sobre MCP' }, slug: 'agents/mcp' },
						{ label: 'MCP tool reference', translations: { es: 'Referencia de herramientas MCP' }, slug: 'agents/tools' },
					],
				},
				{
					label: 'Credentials & providers',
					translations: { es: 'Credenciales y proveedores' },
					items: [
						{ label: 'TOTP codes', translations: { es: 'Códigos TOTP' }, slug: 'guides/totp' },
						{ label: 'Keypairs & signing', translations: { es: 'Pares de claves y firma' }, slug: 'guides/keypairs' },
						{ label: 'Governed ssh-agent', translations: { es: 'ssh-agent gobernado' }, slug: 'guides/ssh-agent' },
						{ label: 'Cloud references', translations: { es: 'Referencias en la nube' }, slug: 'guides/references' },
						{ label: 'Import from 1Password', translations: { es: 'Importar desde 1Password' }, slug: 'guides/import' },
					],
				},
				{
					label: 'Sharing',
					translations: { es: 'Compartir' },
					items: [
						{ label: 'Sealed packages', translations: { es: 'Paquetes sellados' }, slug: 'guides/sharing' },
						{ label: 'USB exchange', translations: { es: 'Intercambio por USB' }, slug: 'guides/usb-exchange' },
					],
				},
				{ label: 'The Web UI', translations: { es: 'La interfaz web' }, slug: 'guides/web-ui' },
				{
					label: 'Operations',
					translations: { es: 'Operación' },
					items: [
						{ label: 'Headless & CI', translations: { es: 'Headless y CI' }, slug: 'operations/headless-ci' },
						{ label: 'Git hooks', translations: { es: 'Hooks de Git' }, slug: 'operations/git-hooks' },
						{ label: 'The audit trail', translations: { es: 'El registro de auditoría' }, slug: 'operations/audit' },
						{ label: 'Backup & recovery', translations: { es: 'Respaldo y recuperación' }, slug: 'operations/backup-recovery' },
						{ label: 'Attended confirmation', translations: { es: 'Confirmación atendida' }, slug: 'operations/attended-confirmation' },
					],
				},
				{
					label: 'Security model',
					translations: { es: 'Modelo de seguridad' },
					items: [
						{ label: 'Secrets in the age of AI Agents', translations: { es: 'Secretos en la era de los agentes de IA' }, slug: 'security/rationale' },
						{ label: 'The decision process', translations: { es: 'El proceso de decisión' }, slug: 'security/decision' },
						{ label: 'Cryptography', translations: { es: 'Criptografía' }, slug: 'security/cryptography' },
						{ label: 'Threat model', translations: { es: 'Modelo de amenazas' }, slug: 'security/threat-model' },
						{ label: 'Flows', translations: { es: 'Flujos' }, slug: 'security/flows' },
					],
				},
				{
					label: 'Reference',
					translations: { es: 'Referencia' },
					items: [
						{ label: 'CLI reference', translations: { es: 'Referencia del CLI' }, slug: 'reference/cli' },
						{ label: 'Configuration', translations: { es: 'Configuración' }, slug: 'reference/configuration' },
						{ label: 'Troubleshooting', translations: { es: 'Solución de problemas' }, slug: 'reference/troubleshooting' },
						{ label: 'FAQ', translations: { es: 'Preguntas frecuentes' }, slug: 'reference/faq' },
						{ label: 'Glossary', translations: { es: 'Glosario' }, slug: 'reference/glossary' },
					],
				},
				{
					label: 'Project',
					translations: { es: 'Proyecto' },
					items: [
						{ label: 'License', translations: { es: 'Licencia' }, slug: 'project/license' },
						{ label: 'Contributing', translations: { es: 'Contribuir' }, slug: 'project/contributing' },
						{ label: 'Support & community', translations: { es: 'Soporte y comunidad' }, slug: 'project/support' },
					],
				},
			],
		}),
	],
});
