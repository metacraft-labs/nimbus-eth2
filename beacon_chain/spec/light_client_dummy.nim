# proc print(value: cdouble) {.importc, cdecl}
import ./all_in_one
proc appender*(a,b: float): seq[float] {.cdecl, exportc, dynlib.} =
  @[a, b]

# proc printAdd*(a,b: string) {.cdecl, exportc, dynlib} =
  # print(appender(a, b))

proc start*() {.exportc: "_start".} =
  discard
