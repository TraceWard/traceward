"""Normalize historical assessment records without changing source evidence."""


def assessment_record(record: dict) -> dict:
    """Expose the neutral judge field for old provider-named result slots.

    Recognize a unique typed result by its shape, never by a model name. Unknown
    or ambiguous fields remain source data rather than a guessed judgement.
    New records with a judge field always take precedence.
    """
    if 'judge' in record:
        return record if isinstance(record['judge'], dict) else {
            **record, 'judge': {'status': 'unavailable', 'reason': 'invalid_judge_record'}}
    candidates = [(key, value) for key, value in record.items()
                  if isinstance(value, dict) and isinstance(value.get('status'), str)
                  and value['status'] in {'assessed', 'scored', 'unavailable'}
                  and any(k in value for k in ('model', 'reason', 'dimensions', 'disposition'))]
    if len(candidates) > 1:
        return {**record, 'judge': {'status': 'unavailable', 'reason': 'ambiguous_historical_judgement'}}
    if not candidates:
        return record
    key, judgement = candidates[0]
    return {**{k: v for k, v in record.items() if k != key}, 'judge': judgement}
