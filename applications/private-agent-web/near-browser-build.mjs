import { readFile } from "node:fs/promises";

// Firefox exposes Request.arrayBuffer(), but not Request.body. The SDK's
// optional stream read otherwise turns every Firefox prompt into empty JSON.
export function nearRequestBodyPlugin() {
  return {
    name: "near-request-body",
    setup(build) {
      build.onLoad({ filter: /[/\\]@nearai[/\\]inference-sdk[/\\]dist[/\\]index\.js$/ }, async ({ path }) => {
        const source = await readFile(path, "utf8");
        const read = "reader = request.clone().body?.getReader();";
        if (!source.includes(read)) throw Error("NEAR SDK request reader changed; check Firefox body handling");
        return { contents: source.replace(read,
          "reader = new Response(await request.clone().arrayBuffer()).body.getReader();"), loader: "js" };
      });
    },
  };
}
