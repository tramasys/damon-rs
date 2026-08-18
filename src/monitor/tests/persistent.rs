use super::*;

#[test]
fn persistent_receipt_round_trips_and_supports_update_and_stop() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = multi_transaction_config();

    let receipt = damon
        .start_persistent(&config)
        .expect("start persistent hierarchy");
    assert_eq!(receipt.kdamond_count(), 2);
    assert_eq!(receipt.identities().len(), 2);
    for index in 0..2 {
        assert_eq!(
            damon.admin.kdamond(index).state().expect("read state"),
            KdamondState::On
        );
    }

    let encoded = receipt.to_bytes().expect("serialize receipt");
    let decoded = PersistentReceipt::from_bytes(&encoded).expect("parse receipt");
    assert_eq!(decoded, receipt);
    let mut attached = damon.attach(&decoded).expect("attach receipt");
    assert_eq!(
        attached.configuration().expect("read configuration"),
        config
    );

    let mut updated = config.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::WillNeed;
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;
    attached
        .update(&updated)
        .expect("update persistent hierarchy");
    assert_eq!(
        attached.configuration().expect("read updated hierarchy"),
        updated
    );

    attached.stop().expect("stop persistent hierarchy");
    assert!(attached.receipt().identities().is_empty());
    for index in 0..2 {
        assert_eq!(
            damon.admin.kdamond(index).state().expect("read state"),
            KdamondState::Off
        );
    }
}

#[test]
fn persistent_attach_rejects_configuration_and_pid_replacement() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = multi_transaction_config();
    damon
        .stage_configuration(&config)
        .expect("stage preceding hierarchy");
    let future = "kdamonds/0/contexts/0/future_persistent_input";
    model.set_file(future, b"preserve\n");
    let receipt = damon
        .start_persistent(&config)
        .expect("start persistent hierarchy");
    let action = "kdamonds/0/contexts/0/schemes/0/action";
    model.set_file(action, b"pageout\n");

    assert!(matches!(
        damon.attach(&receipt),
        Err(Error::OwnershipLost { .. })
    ));

    model.set_file(action, b"stat\n");
    model.set_file(future, b"changed\n");
    assert!(matches!(
        damon.attach(&receipt),
        Err(Error::OwnershipLost { .. })
    ));

    model.set_file(future, b"preserve\n");
    let expected_pid = receipt.identities()[1].pid();
    model.set_file("kdamonds/1/pid", b"999999\n");
    assert!(matches!(
        damon.attach(&receipt),
        Err(Error::OwnershipLost { .. })
    ));

    model.set_file(
        "kdamonds/1/pid",
        format!("{}\n", expected_pid.get()).as_bytes(),
    );
    let mut attached = damon.attach(&receipt).expect("reattach repaired hierarchy");
    attached.stop().expect("stop hierarchy");
}

#[test]
fn persistent_partial_stop_refreshes_the_remaining_identities() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let receipt = damon
        .start_persistent(&multi_transaction_config())
        .expect("start persistent hierarchy");
    let mut attached = damon.attach(&receipt).expect("attach receipt");
    model.fail_next_write("kdamonds/0/state", 22);

    assert!(matches!(attached.stop(), Err(Error::Io { .. })));
    assert_eq!(attached.receipt().identities().len(), 1);
    assert_eq!(attached.receipt().identities()[0].index(), 0);
    assert_eq!(
        damon.admin.kdamond(0).state().expect("read first state"),
        KdamondState::On
    );
    assert_eq!(
        damon.admin.kdamond(1).state().expect("read second state"),
        KdamondState::Off
    );

    attached.stop().expect("retry remaining stop");
    assert!(attached.receipt().identities().is_empty());
}

#[test]
fn receipt_parser_rejects_truncation_and_trailing_data() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let receipt = damon
        .start_persistent(&transaction_config(42, Action::Stat))
        .expect("start persistent hierarchy");
    let bytes = receipt.to_bytes().expect("serialize receipt");
    assert!(matches!(
        PersistentReceipt::from_bytes(&bytes[..bytes.len() - 1]),
        Err(Error::InvalidReceipt { .. })
    ));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        PersistentReceipt::from_bytes(&trailing),
        Err(Error::InvalidReceipt { .. })
    ));

    let mut attached = damon.attach(&receipt).expect("attach receipt");
    attached.stop().expect("stop hierarchy");
}
