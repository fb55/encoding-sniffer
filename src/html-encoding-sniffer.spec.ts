/**
 * This file, and the __fixtures__ directory, were adapted from the
 * html-encoding-sniffer module, copyright © Domenic Denicola.
 *
 * See __fixtures__/LICENSE.txt for full license terms.
 */

import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "vitest";
import { getEncoding as htmlEncodingSniffer } from "./index.js";

function read(relative: string): Uint8Array {
    // Test that the module works with Uint8Arrays, not just Buffers:
    const buffer = fs.readFileSync(
        path.resolve(__dirname, "__fixtures__", relative),
    );
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
}

describe("A file with a UTF-8 BOM", () => {
    const buffer = read("utf-8-bom.html");

    it("should sniff as UTF-8, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "UTF-8");
    });

    it("should sniff as UTF-8, given overriding options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1252",
            defaultEncoding: "UTF-16LE",
        });

        assert.strictEqual(sniffedEncoding, "UTF-8");
    });
});

describe("A file with a UTF-16LE BOM", () => {
    const buffer = read("utf-16le-bom.html");

    it("should sniff as UTF-16LE, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "UTF-16LE");
    });

    it("should sniff as UTF-16LE, given overriding options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1252",
            defaultEncoding: "UTF-8",
        });

        assert.strictEqual(sniffedEncoding, "UTF-16LE");
    });
});

describe("A file with a UTF-16BE BOM", () => {
    const buffer = read("utf-16be-bom.html");

    it("should sniff as UTF-16BE, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "UTF-16BE");
    });

    it("should sniff as UTF-16BE, given overriding options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1252",
            defaultEncoding: "UTF-8",
        });

        assert.strictEqual(sniffedEncoding, "UTF-16BE");
    });
});

describe("A file with no BOM and no <meta charset>", () => {
    const buffer = read("no-bom-no-charset.html");

    it("should sniff as windows-1252, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "windows-1252");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the default encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-16");
    });
});

describe("A file with no BOM and a <meta charset>", () => {
    const buffer = read("no-bom-charset-koi8.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "KOI8-R");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "KOI8-R");
    });
});

describe("A file with no BOM and a <meta http-equiv>", () => {
    const buffer = read("no-bom-charset-http-equiv-tis-620.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "windows-874");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-874");
    });
});

describe("A file with no BOM and a <meta http-equiv> with no quotes", () => {
    const buffer = read("no-bom-charset-http-equiv-no-quotes.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "ISO-8859-5");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-5");
    });
});

describe("A file with no BOM and a ><meta charset>", () => {
    const buffer = read("no-bom-charset-bracket.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "UTF-8");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "UTF-8");
    });
});

describe("A file with no BOM and a <meta charset> preceeded by a short comment <!-->", () => {
    const buffer = read("no-bom-charset-short-comment.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });
});

describe("A file with no BOM and a <meta http-equiv> ending with a trailing space", () => {
    const buffer = read("no-bom-charset-http-equiv-trailing-space.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });
});

describe("A file with no BOM and a <meta http-equiv> with 'charsetcharset'", () => {
    const buffer = read("no-bom-charset-http-equiv-second-charset.html");

    it("should sniff as the charset value, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the charset value, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-2");
    });
});

describe("A file with no BOM and a <meta http-equiv=refresh> with another http-equiv", () => {
    const buffer = read("no-bom-charset-http-equiv-refresh.html");

    it("should sniff as windows-1252, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "windows-1252");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as the default encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "ISO-8859-16");
    });
});

for (const utf16Encoding of ["utf-16be", "utf-16", "utf-16le"]) {
    describe(`A file with a BOM and a <meta charset> of ${utf16Encoding}`, () => {
        const buffer = read(`no-bom-charset-${utf16Encoding}.html`);

        it("should sniff as UTF-8, given no options", () => {
            const sniffedEncoding = htmlEncodingSniffer(buffer);

            assert.strictEqual(sniffedEncoding, "UTF-8");
        });

        it("should sniff as the transport layer encoding, given that", () => {
            const sniffedEncoding = htmlEncodingSniffer(buffer, {
                transportLayerEncodingLabel: "windows-1251",
                defaultEncoding: "ISO-8859-16",
            });

            assert.strictEqual(sniffedEncoding, "windows-1251");
        });

        it("should sniff as UTF-8, given only a default encoding", () => {
            const sniffedEncoding = htmlEncodingSniffer(buffer, {
                defaultEncoding: "ISO-8859-16",
            });

            assert.strictEqual(sniffedEncoding, "UTF-8");
        });
    });
}

describe("A file with a BOM and a <meta charset> of x-user-defined", () => {
    const buffer = read(`no-bom-charset-x-user-defined.html`);

    it("should sniff as windows-1252, given no options", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer);

        assert.strictEqual(sniffedEncoding, "windows-1252");
    });

    it("should sniff as the transport layer encoding, given that", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            transportLayerEncodingLabel: "windows-1251",
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1251");
    });

    it("should sniff as windows-1252, given only a default encoding", () => {
        const sniffedEncoding = htmlEncodingSniffer(buffer, {
            defaultEncoding: "ISO-8859-16",
        });

        assert.strictEqual(sniffedEncoding, "windows-1252");
    });
});
