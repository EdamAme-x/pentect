# Pentect docs demo video

Remotion source for the video embedded on the Pentect docs homepage. It keeps the AI client visible,
shows the secret becoming a handle at the Pentect boundary, and restores it only
for the local command.

```sh
npm install
npm run dev
```

Render the full-resolution video and poster directly into `website/public`:

```sh
npm run render
npm run poster
```

`frame.md` records the visual rules used by the composition. Every credential in
the demo is synthetic.
