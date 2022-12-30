import { Transform, type TransformCallback } from "node:stream";
import iconv from "iconv-lite";
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
    options: SnifferOptions = {}
): string {
    return iconv.decode(buffer, getEncoding(buffer, options));
}

/**
 * Decodes a stream of buffers into a stream of strings.
 *
 * Reads the first 1024 bytes and passes them to the sniffer. Once an encoding
 * has been determined, it passes all data to iconv-lite's stream and outputs
 * the results.
 */
export class DecodeStream extends Transform {
    private readonly sniffer: Sniffer;
    private readonly buffers: Uint8Array[] = [];
    /** The iconv decode stream. If it is set, we have read more than `options.maxBytes` bytes. */
    private iconv: NodeJS.ReadWriteStream | null = null;
    private readonly maxBytes;
    private readBytes = 0;

    constructor(options?: SnifferOptions) {
        super({ decodeStrings: false, encoding: "utf-8" });
        this.sniffer = new Sniffer(options);
        this.maxBytes = options?.maxBytes ?? 1024;
    }

    override _transform(
        chunk: Uint8Array,
        _encoding: string,
        callback: TransformCallback
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

        this.getIconvStream().write(chunk, callback);
    }

    private getIconvStream(): NodeJS.ReadWriteStream {
        if (this.iconv) {
            return this.iconv;
        }

        const stream = iconv.decodeStream(this.sniffer.encoding);
        stream.on("data", (chunk: string) => this.push(chunk, "utf-8"));
        stream.on("end", () => this.push(null));

        this.iconv = stream;

        for (const buffer of this.buffers) {
            stream.write(buffer);
        }
        this.buffers.length = 0;

        return stream;
    }

    override _flush(callback: TransformCallback): void {
        this.getIconvStream().end(callback);
    }
}

export { type SnifferOptions, getEncoding } from "./sniffer.js";
