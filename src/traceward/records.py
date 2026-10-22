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


def effective_assessment(record: dict, revisions: list[dict]) -> dict:
    """Read-only presentation of a verdict retained across a failed later attempt."""
    current = assessment_record(record)
    judge = current.get('judge', {})
    state = ('cancelled' if judge.get('reason') == 'assessment_cancelled_on_shutdown' else
             'pending' if judge.get('status') == 'pending' else
             'assessed' if judge.get('status') in {'assessed', 'scored'} else
             'unavailable' if judge else 'pending')
    effective, revision, error = (judge, current.get('revision'), None) if state == 'assessed' else (None, None, None)
    retained = current.get('retained_review_revision')
    if retained is not None and effective is None:
        prior = next((assessment_record(r) for r in revisions
                      if r.get('finding_id') == current.get('finding_id') and r.get('revision') == retained), None)
        if (prior and prior.get('status') == 'review_required'
                and prior.get('judge', {}).get('status') in {'assessed', 'scored'}
                and set(prior.get('evidence_ids', [])) == set(current.get('evidence_ids', []))
                and set(prior.get('consequential_evidence_ids', [])) == set(current.get('consequential_evidence_ids', []))
                and prior.get('analysis_window') == current.get('analysis_window')
                and prior.get('tool_use_id') == current.get('tool_use_id')):
            effective, revision = prior['judge'], retained
        else:
            error = 'Retained assessment missing or its evidence scope does not match'
    return {**current, 'effective_judge': effective, 'effective_judge_revision': revision,
            'assessment_attempt_status': state, 'effective_judge_error': error}
