import { Sniffer, ResultType, STRINGS } from "./sniffer.js";

const XML_ENCODING = "<?xml encoding='utf-16'>";
const META_CONTENT =
    "<meta http-equiv='content-type' content=charset=iso-8859-2>";

const META_CHARSET = "<meta charset=iso-8859-2>";

describe("Sniffer", () => {
    it("should recognize XML ", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(XML_ENCODING));
        expect(sniffer.encoding).toBe("UTF-8");
        expect(sniffer.resultType).toBe(ResultType.XML_ENCODING);
    });

    it("should recognize HTML meta tag charset, lower", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CHARSET));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag charset, upper", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CHARSET.toUpperCase()));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag charset, quoted", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from("<Meta Charset  =  ' ISO-8859-2 '>"));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, lower", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CONTENT));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, upper", () => {
        const sniffer = new Sniffer();
        sniffer.write(Buffer.from(META_CONTENT.toUpperCase()));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, byte-by-byte", () => {
        const sniffer = new Sniffer();
        for (const c of META_CONTENT) sniffer.write(Buffer.from(c));
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should not recognize HTML meta tag http-equiv, if not within 1024 bytes", () => {
        const sniffer = new Sniffer();
        sniffer.write(
            Buffer.from("a".repeat(1010) + META_CONTENT.toUpperCase()),
        );
        expect(sniffer.encoding).toBe("windows-1252");
        expect(sniffer.resultType).toBe(ResultType.DEFAULT);
    });

    it("should recognize HTML meta tag http-equiv, with additional content", () => {
        const sniffer = new Sniffer();
        sniffer.write(
            Buffer.from(`${XML_ENCODING}<foo></foo> <bar baz><! ><!-- 
            foo --><mEtA foo=bar boo="hoo" content ="charsetsomethingcchArset  
            =\t'  windows-1254';other" http-EQUIV = contenT-tYpe>${META_CONTENT}`),
        );
        expect(sniffer.encoding).toBe("windows-1254");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, quoted attrib unquoted value", () => {
        const sniffer = new Sniffer();
        sniffer.write(
            Buffer.from(
                "<!---><meta http-equiv='content-type' content='CHARSET=x-user-defined'>",
            ),
        );
        expect(sniffer.encoding).toBe("windows-1252");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should recognize HTML meta tag http-equiv, unquoted attrib quoted value", () => {
        const sniffer = new Sniffer();
        sniffer.write(
            Buffer.from(
                "<!--><meta http-equiv='content-type' content=CHARSET='UTF-16BE'>",
            ),
        );
        expect(sniffer.encoding).toBe("UTF-8");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should ignore duplicate meta content attributes", () => {
        const sniffer = new Sniffer();
        sniffer.write(
            Buffer.from(
                "<meta content=CHARSET='iso-8859-2' content=charset=UTF-16LE http-equiv='content-type'>",
            ),
        );
        expect(sniffer.encoding).toBe("ISO-8859-2");
        expect(sniffer.resultType).toBe(ResultType.META_TAG);
    });

    it("should support XML UTF-16LE prefixes", () => {
        const sniffer = new Sniffer();
        sniffer.write(STRINGS.UTF16LE_XML_PREFIX);
        expect(sniffer.encoding).toBe("UTF-16LE");
        expect(sniffer.resultType).toBe(ResultType.XML_PREFIX);
    });

    it("should support XML UTF-16BE prefixes", () => {
        const sniffer = new Sniffer();
        sniffer.write(STRINGS.UTF16BE_XML_PREFIX);
        expect(sniffer.encoding).toBe("UTF-16BE");
        expect(sniffer.resultType).toBe(ResultType.XML_PREFIX);
    });

    it("should support UTF-8 BOMs", () => {
        const sniffer = new Sniffer();
        sniffer.write(STRINGS.UTF8_BOM);
        expect(sniffer.encoding).toBe("UTF-8");
        expect(sniffer.resultType).toBe(ResultType.BOM);
    });

    it("should support UTF-16LE BOMs", () => {
        const sniffer = new Sniffer();
        sniffer.write(STRINGS.UTF16LE_BOM);
        expect(sniffer.encoding).toBe("UTF-16LE");
        expect(sniffer.resultType).toBe(ResultType.BOM);
    });

    it("should support UTF-16BE BOMs", () => {
        const sniffer = new Sniffer();
        sniffer.write(STRINGS.UTF16BE_BOM);
        expect(sniffer.encoding).toBe("UTF-16BE");
        expect(sniffer.resultType).toBe(ResultType.BOM);
    });
});
