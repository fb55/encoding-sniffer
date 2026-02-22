import { createReadStream, promises as fs, readdirSync } from "node:fs";
import path from "node:path";
import { setTimeout } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { DecodeStream } from "./index.js";

function getStream(stream: NodeJS.ReadableStream): Promise<string> {
    // TODO[engines.node@>=18]: Use `reduce`
    return new Promise((resolve, reject) => {
        let data = "";
        stream.on("data", (chunk) => {
            expect(typeof chunk).toBe("string");
            data += chunk;
        });
        stream.on("end", () => resolve(data));
        stream.on("error", reject);
        stream.resume();
    });
}

describe("DecodeStream", () => {
    it("should decode a UTF-8 string", async () => {
        const stream = new DecodeStream();
        stream.end(Buffer.from("Hello, world!"));
        expect(await getStream(stream)).toBe("Hello, world!");
    });

    describe("Fixtures", () => {
        for (const file of readdirSync(path.join(__dirname, "__fixtures__"))) {
            if (!file.endsWith(".html")) continue;

            it(`should decode ${file}`, async () => {
                const stream = new DecodeStream();
                createReadStream(
                    path.join(__dirname, "__fixtures__", file),
                ).pipe(stream);
                expect(await getStream(stream)).toMatchSnapshot();
            });
        }
    });

    it("should decode a file one byte at a time", async () => {
        const file = await fs.readFile(
            path.join(__dirname, "__fixtures__", "utf-16be-bom.html"),
        );
        const stream = new DecodeStream();
        const collector = getStream(stream);
        for (let index = 0; index < file.length; index++) {
            // Wait for a bit to allow the stream to process the data.
            await setTimeout(0);
            stream.write(file.slice(index, index + 1));
        }
        stream.end();
        expect(await collector).toMatchSnapshot();
    });
});
