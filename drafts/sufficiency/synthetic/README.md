# Synthetic lines — clearly labelled, not corpus

`panos-doubled-quote.log` is **synthetic**: the first PAN-OS TRAFFIC line from the Beats corpus with
the rule-name cell replaced by `"rule ""quoted"" name, with comma"`, because no corpus line exercises
the doubled-quote escape the PAN-OS CSV convention declares. Expected decode of that cell:
`rule "quoted" name, with comma`. It exists only to exercise `csv.escape = doubled`; it must never be
counted in any coverage or agreement figure.
