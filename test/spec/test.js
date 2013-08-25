/*global describe, it */
'use strict';

/*
Yes, I know the syntax is really weird.  Yeoman set that up... I do
not understand JavaScript developers. But this thing has a cute
phantomjs runner so let's just stick with it unless
expect(it).gets.to.be.way.too.irritating.
*/

// Apparently PhantomJS is terrible.
if (!Function.prototype.bind) {
  Function.prototype.bind = function (oThis) {
    if (typeof this !== "function") {
      // closest thing possible to the ECMAScript 5 internal IsCallable function
      throw new TypeError("Function.prototype.bind - what is trying to be bound is not callable");
    }

    var aArgs = Array.prototype.slice.call(arguments, 1),
    fToBind = this,
    fNOP = function () {},
    fBound = function () {
      return fToBind.apply(this instanceof fNOP && oThis
                           ? this
                           : oThis,
                           aArgs.concat(Array.prototype.slice.call(arguments)));
    };

    fNOP.prototype = this.prototype;
    fBound.prototype = new fNOP();

    return fBound;
  };
}

(function () {
  describe('ztext parser', function() {
    function ztextTreeEquals(a, b) {
      if (a.length !== b.length)
        return false;
      for (var i = 0; i < a.length; i++) {
        if (typeof a[i] == "string" || typeof b[i] == "string") {
          if (a[i] !== b[i])
            return false;
        } else {
          if (a[i].tag !== b[i].tag ||
              a[i].open !== b[i].open ||
              a[i].close !== b[i].close ||
              !ztextTreeEquals(a[i].children, b[i].children))
            return false;
        }
      }
      return true;
    }

    it('should parse strings as is', function() {
      expect(ztextTreeEquals(
        parseZtext("foo{}"),
        ["foo{}"]
      )).to.be.true;
    });

    it('should parse a bolded string', function() {
      expect(ztextTreeEquals(
        parseZtext("moo @bold{moo}"),
        ["moo ", new ZtextNode("bold", "{", "}", ["moo"])]
      )).to.be.true;
    });

    it('should handle all types of delimiters', function() {
      expect(ztextTreeEquals(
        parseZtext("@<moo @bold{moo} @asdf(parens)>"),
        [
          new ZtextNode("", "<", ">", [
            "moo ",
            new ZtextNode("bold", "{", "}", ["moo"]),
            " ",
            new ZtextNode("asdf", "(", ")", ["parens"])
          ])
        ]
      )).to.be.true;
    });

    it('should never insert empty strings', function() {
      expect(ztextTreeEquals(
        parseZtext(""),
        [ ]
      )).to.be.true;

      expect(ztextTreeEquals(
        parseZtext("@{}"),
        [ new ZtextNode("", "{", "}", []) ]
      )).to.be.true;
    });

    it('should parse escaped @ signs', function() {
      expect(ztextTreeEquals(
        parseZtext("foo@@bar@@@@@@"),
        [ "foo@bar@@@" ]
      )).to.be.true;
    });

    it('should treat syntax errors as plain text', function() {
      expect(ztextTreeEquals(
        parseZtext("foo@bar {}"),
        [ "foo@bar {}" ]
      )).to.be.true;
    });

    it('should allow numbers and _ in tag names', function() {
      expect(ztextTreeEquals(
        parseZtext("@aAzZ_09{moo}"),
        [ new ZtextNode("aAzZ_09", "{", "}", ["moo"]) ]
      )).to.be.true;
    });
  })

  describe('event target', function() {
    it('should behave correctly when manipulated mid-dispatch', function() {
      var handlerLog = [];
      var target = new RoostEventTarget();

      function handler0() {
        handlerLog.push(0);
      }
      function handler1() {
        handlerLog.push(1);
        target.removeEventListener("test", handler0);
        target.removeEventListener("test", handler2);
        target.addEventListener("test", handler3);
      }
      function handler2() {
        handlerLog.push(2);
      }
      function handler3() {
        handlerLog.push(3);
      }

      target.addEventListener("test", handler0);
      target.addEventListener("test", handler1);
      target.addEventListener("test", handler2);

      handlerLog = [];
      target.dispatchEvent({type: "test"});
      expect(handlerLog).to.deep.equal([0, 1]);

      handlerLog = [];
      target.dispatchEvent({type: "test"});
      expect(handlerLog).to.deep.equal([1, 3]);

      handlerLog = [];
      target.dispatchEvent({type: "test"});
      expect(handlerLog).to.deep.equal([1, 3]);
    });
  });

  describe('url finder', function() {
    function UrlTest() {
      this.log_ = [];
      this.expected_ = [];
    };
    UrlTest.prototype.expectUrl = function(url) {
      this.expected_.push(['url', url]);
    };
    UrlTest.prototype.expectText = function(text) {
      this.expected_.push(['text', text]);
    };
    UrlTest.prototype.gotUrl_ = function(url) {
      this.log_.push(['url', url]);
    };
    UrlTest.prototype.gotText_ = function(text) {
      this.log_.push(['text', text]);
    };
    UrlTest.prototype.run = function(str) {
      findUrls(str,
               this.gotUrl_.bind(this),
               this.gotText_.bind(this));
      expect(this.log_).to.deep.equal(this.expected_);
    };

    it('should parse multiple URLs', function() {
      var test = new UrlTest();
      test.expectText("Roost lives at ");
      test.expectUrl("https://roost.mit.edu");
      test.expectText(", not at ");
      test.expectUrl("http://roost.mit.edu");
      test.expectText(".");
      test.run(
        "Roost lives at https://roost.mit.edu, not at http://roost.mit.edu.");
    });

    it('should never give empty strings', function() {
      var test = new UrlTest();
      test.expectUrl("https://roost.mit.edu");
      test.run("https://roost.mit.edu");
    });

    it('should handle parenthesis', function() {
      var test = new UrlTest();
      test.expectText("(This URL is ");
      test.expectUrl("https://en.wikipedia.org/wiki/Owl_(disambiguation)");
      test.expectText(")");
      test.run("(This URL is https://en.wikipedia.org/wiki/Owl_(disambiguation))")
    });

    it('should start at word boundaries', function() {
      var test = new UrlTest();
      test.expectText("mooohttp://example.com");
      test.run("mooohttp://example.com");
    });

    it('should allow unicode hostnames', function() {
      var test = new UrlTest();
      test.expectUrl("http://☃.net");
      test.run("http://☃.net");
    });

    it('should allow port numbers', function() {
      var test = new UrlTest();
      test.expectUrl("https://davidben.net:443/is-crazy.txt");
      test.run("https://davidben.net:443/is-crazy.txt");
    });
  });

  describe('long zuser', function() {
    it('should expand simple strings', function() {
      expect(longZuser("davidben")).to.be.equal("davidben@ATHENA.MIT.EDU");
    });

    it('should not expand cross-realm principals', function() {
      expect(longZuser("davidben@ZONE.MIT.EDU")).to.be.equal(
        "davidben@ZONE.MIT.EDU");
    });

    it('should not expand the empty recipient', function() {
      expect(longZuser("")).to.be.equal("");
    });

    it('should handle trailing @s', function() {
      expect(longZuser("davidben@")).to.be.equal("davidben@ATHENA.MIT.EDU");
    });
  });

  describe('short zuser', function() {
    it('should strip off the default realm', function() {
      expect(shortZuser("davidben@ATHENA.MIT.EDU")).to.be.equal("davidben");
    });

    it('should not shorten cross-realm principals', function() {
      expect(shortZuser("davidben@ZONE.MIT.EDU")).to.be.equal(
        "davidben@ZONE.MIT.EDU");
    });

    it('should handle trailing @s', function() {
      expect(shortZuser("davidben@")).to.be.equal("davidben");
    });
  });

  describe('zuser realm', function() {
    it('should handle the default realm', function() {
      expect(zuserRealm("davidben")).to.be.equal("ATHENA.MIT.EDU");
      expect(zuserRealm("")).to.be.equal("ATHENA.MIT.EDU");
    });

    it('should handle cross-realm recipients', function() {
      expect(zuserRealm("@ZONE.MIT.EDU")).to.be.equal("ZONE.MIT.EDU");
      expect(zuserRealm("davidben@ZONE.MIT.EDU")).to.be.equal("ZONE.MIT.EDU");
    });

    it('should handle trailing @s', function() {
      expect(zuserRealm("davidben@")).to.be.equal("ATHENA.MIT.EDU");
      expect(zuserRealm("@")).to.be.equal("ATHENA.MIT.EDU");
    });
  });
})();
