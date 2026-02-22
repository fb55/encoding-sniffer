import { describe, expect, it } from "vitest";
import { ResultType, Sniffer } from "./sniffer.js";

const XML_ENCODING = "<?xml encoding='Shift_JIS'>";
const META_CONTENT =
    "<meta http-equiv='content-type' content=charset=Shift_JIS>";

const META_CHARSET = "<meta charset=Shift_JIS>";

describe("Sniffer", () => {
    it("should recognize XML ", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(XML_ENCODING));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.XML_ENCODING);
    });

    it("should recognize HTML meta tag charset, lower", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CHARSET));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag charset, upper", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CHARSET.toUpperCase()));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag charset, quoted", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from("<Meta Charset  =  ' Shift_JIS '>"));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, lower", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CONTENT));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, upper", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CONTENT.toUpperCase()));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, byte-by-byte", () => {
        const sniffer = new Sniffer();
        for (const c of META_CONTENT) sniffer.write(Buffer.from(c));
        expect(sniffer.encoding).toBe("Shift_JIS");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });
});
