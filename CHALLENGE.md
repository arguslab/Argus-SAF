# Amandroid challenges

Before you take one of the challenges, please contact [`@fgwei`](https://github.com/fgwei) to let him aware. And put a mark (e.g., Resolving by [`@fgwei`](https://github.com/fgwei)) in the end of the challenge to avoid any situation of conflict. You can create a PR following guidance in [CONTRIBUTING.md](CONTRIBUTING.md) after you resolved it. 

## Continuous tasks

`#c1`. All the APIs should be documented. (Post by [`@fgwei`](https://github.com/fgwei))

`#c2`. Error handling in the code need to be cleaned. (Post by [`@fgwei`](https://github.com/fgwei))

`#c3`. Amandroid documentations need to be revised. (Post by [`@fgwei`](https://github.com/fgwei))(Resolving by [`@fgwei`](https://github.com/fgwei))

## org.argus.jawa.alir
In package `org.argus.jawa.alir.pta.reachingFactsAnalysis.model`:

- `#c4`. We need to add more models for java apis. (Post by [`@fgwei`](https://github.com/fgwei))
- `#c5`. Models actually sharing similar desings, the best way of doing it is designing a DSL to write the model in a simpler way and generate the model codes automatically. (Important!) (Post by [`@fgwei`](https://github.com/fgwei))
- `#c6`. API model need to be redesigned to input/output general datas, which allows multiple points-to analysis can share the same model, e.g., SuperSpark and RFA.  (Post by [`@fgwei`](https://github.com/fgwei))

`#c7`. In package `org.argus.jawa.alir.taintAnalysis`, we need to implement monotonic data flow analysis based on demand taint analysis, many situations need such analysis to get better performance. (Post by [`@fgwei`](https://github.com/fgwei))

## org.argus.amandroid.core
`#c8`. In package `org.argus.amandroid.core.parser`, the LayoutFileParser.scala and ManifestParser.scala only can handle plain text xml files. Better design is to read from raw xml files from apk directly, and parse the equivalent information as current parsers. (Important!) (Post by [`@fgwei`](https://github.com/fgwei))

`#c9`. In package `org.argus.amandroid.core.appInfo`, the ReachableInfoCollector.scala need to be updated for adding more callbacks. (Post by [`@fgwei`](https://github.com/fgwei))

In package `org.argus.amandroid.core.dedex`,
- `#c10`. Register type resolving in DedexTypeResolver.scala and DexInstructionToPilarParser.scala need to be tested and cleaned (or even redesigned). The main beast is the const4 resoling, as it can be `int`/`short`/`boolean` 0 or `object` null. (Important!) (Post by [`@fgwei`](https://github.com/fgwei))
- `#c11`. Make the decompiling process faster. (Post by [`@fgwei`](https://github.com/fgwei))


## org.argus.amandroid.alir
In package `org.argus.amandroid.alir.pta.reachingFactsAnalysis.model`:

- `#c12`. We need to add more models for android apis. (Post by [`@fgwei`](https://github.com/fgwei))
- `#c13`. Models actually sharing similar desings, the best way of doing it is designing a DSL to write the model in a simpler way and generate the model codes automatically. (Important!) (Post by [`@fgwei`](https://github.com/fgwei))


`#c14`. Package `org.sireum.amandroid.java` need to be added, and developing jawa to java translator. (Major task.) (Post by [`@fgwei`](https://github.com/fgwei))

