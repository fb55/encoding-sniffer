import { Transform, type TransformCallback } from "node:stream";
// eslint-disable-next-line n/no-missing-import
import { TextDecoder } from "@exodus/bytes/encoding.js";
import type { SnifferOptions } from "./sniffer.js";
import { Sniffer, getEncoding } from "./sniffer.js";

/**
 * Sniff the encoding of a buffer, then decode it.
 *
 * @param buffer Buffer to be decoded
 * @param options Options for the sniffer
 * @returns The decoded buffer
 */
export function decodeBuffer(
    buffer: Buffer,
    options: SnifferOptions = {},
): string {
    const encoding = getEncoding(buffer, options);
    const decoder = new TextDecoder(encoding);
    return decoder.decode(buffer);
}

/**
 * Decodes a stream of buffers into a stream of strings.
 *
 * Reads the first 1024 bytes and passes them to the sniffer. Once an encoding
 * has been determined, it decodes all buffered data and outputs the results.
 */
export class DecodeStream extends Transform {
    private readonly sniffer: Sniffer;
    private readonly buffers: Uint8Array[] = [];
    /** The TextDecoder instance. If set, we have determined the encoding. */
    private decoder: TextDecoder | null = null;
    private readonly maxBytes: number;
    private readBytes = 0;

    constructor(options?: SnifferOptions) {
        super({ decodeStrings: false, encoding: "utf-8" });
        this.sniffer = new Sniffer(options);
        this.maxBytes = options?.maxBytes ?? 1024;
    }

    override _transform(
        chunk: Uint8Array,
        _encoding: string,
        callback: TransformCallback,
    ): void {
        if (this.readBytes < this.maxBytes) {
            this.sniffer.write(chunk);
            this.readBytes += chunk.length;

            if (this.readBytes < this.maxBytes) {
                this.buffers.push(chunk);
                callback();
                return;
            }
        }

        const decoder = this.getDecoder();
        const decoded = decoder.decode(chunk, { stream: true });
        if (decoded) {
            this.push(decoded, "utf-8");
        }
        callback();
    }

    private getDecoder(): TextDecoder {
        if (this.decoder) {
            return this.decoder;
        }

        this.decoder = new TextDecoder(this.sniffer.encoding);

        // Process all buffered chunks
        for (const buffer of this.buffers) {
            const decoded = this.decoder.decode(buffer, { stream: true });
            if (decoded) {
                this.push(decoded, "utf-8");
            }
        }
        this.buffers.length = 0;

        return this.decoder;
    }

    override _flush(callback: TransformCallback): void {
        const decoder = this.getDecoder();
        // Flush any remaining bytes
        const decoded = decoder.decode();
        if (decoded) {
            this.push(decoded, "utf-8");
        }
        callback();
    }
}

export { type SnifferOptions, getEncoding } from "./sniffer.js";
