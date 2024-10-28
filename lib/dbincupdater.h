#include <set>
#include <map>

template <class T>
class DBIncUpdater
{
public:
    DBIncUpdater() = default;
    ~DBIncUpdater() = default;
    DBIncUpdater(const DBIncUpdater&) = delete;
    DBIncUpdater& operator=(const DBIncUpdater&) = delete;
    DBIncUpdater(DBIncUpdater&&) = delete;
    DBIncUpdater& operator=(DBIncUpdater&&) = delete;

    void init(DBConnector* db, const string& tableName)
    {
        m_table = make_unique<T>(db, tableName);
    }

    DBIncUpdater& build(const string& key, const FieldValueTuple& fv)
    {
        if (!m_table) return *this;
        auto fv_itr = cache.find(key);
        if (fv_itr != cache.end())
        {
            for (auto& current_fv: fv_itr->second)
            {
                if (fvField(current_fv) == fvField(fv))
                {
                    fvValue(current_fv) = fvValue(fv);
                    return *this;
                }
            }
            fv_itr->second.push_back(fv);
        }
        else
        {
            std::vector<FieldValueTuple> vec = {fv};
            cache.insert({key, vec});
        }
        return *this;
    }

    DBIncUpdater& build(const string& key, const string& field, const string& value)
    {
        if (!m_table) return *this;
        FieldValueTuple fv = {field, value};
        return build(key, fv);
    }

    DBIncUpdater& write(const KeyOpFieldsValuesTuple& kfv)
    {
        if (!m_table) return *this;
        if (kfvOp(kfv) != SET_COMMAND and cache.find(kfvKey(kfv)) != cache.end())
        {
            cache.erase(cache.find(kfvKey(kfv)));
            write(kfvKey(kfv));
            return *this;
        }

        cache[kfvKey(kfv)] = kfvFieldsValues(kfv);
        write(kfvKey(kfv));
        return *this;
    }

    DBIncUpdater& write(const string& key)
    {
        /* If not present in the cache, assumed as a del request */
        if (!m_table) return *this;
        auto fv_itr = cache.find(key);
        if (fv_itr != cache.end())
        {
            m_table->set(key, fv_itr->second);
        }
        else
        {
            m_table->del(key); // Delete from DB is missing from cache
        }
        return *this;
    }

    DBIncUpdater& destroy(const string& key)
    {
        if (!m_table) return *this;
        if (cache.find(key) != cache.end())
        {
            cache.erase(cache.find(key));
        }
        return *this;
    }

    bool hget(const std::string& key, const std::string& field, std::string& value)
    {
        auto fv_itr = cache.find(key);
        if (fv_itr == cache.end())
        {
            return false;
        }
        for (auto& current_fv: fv_itr->second)
        {
            if (fvField(current_fv) == field)
            {
                value = fvValue(current_fv);
                return true;
            }
        }
        return false;
    }
    // TODO: DBIncUpdater& build(const string& key, std::vector<FieldValueTuple>&);
    // TODO: DBIncUpdater& destroy(const string& key, const string& field);
protected:
    typedef std::unordered_map<std::string, std::vector<FieldValueTuple>> TableCache;
    TableCache cache;
    std::unique_ptr<T> m_table;
};


// namespace dbincupdater_ut
// {
//     string getCachedValue(DBIncUpdater<Table>& updater, const string& key, const string& field)
//     {
//        string val;
//        updater.hget(key, field, val);
//        return val;
//     }

//     TEST(DBIncUpdaterTest, TestInterfcae)
//     {
//        testing_db::reset();

//        std::string recv_val;
//        DBConnector db_conn("APPL_DB", 0);
//        DBIncUpdater<Table> updater;

//        updater.init(&db_conn, std::string("test_table"));
//        EXPECT_EQ(updater.cache["key1"].size(), 0);

//        FieldValueTuple fv("test_f", "test_v");

//        updater.build("key1", fv)
//               .build("key1", "test_f2", "test_v2")
//               .build("key2", "test_f21", "test_v21");

//        // Check if the cache contains the expected data
//        EXPECT_EQ(updater.cache["key1"].size(), 2);
//        EXPECT_EQ(getCachedValue(updater, "key1", "test_f"), "test_v");
//        EXPECT_EQ(getCachedValue(updater, "key1", "test_f2"), "test_v2");

//        EXPECT_EQ(updater.cache["key2"].size(), 1);
//        EXPECT_EQ(getCachedValue(updater, "key2", "test_f21"), "test_v21");

//        FieldValueTuple fv2("test_f22", "test_v22");
//        updater.build("key2", fv2)
//               .build("key2", "test_f21", "test_v212") // Update existing entry
//               .write("key2"); // Write to DB

//        EXPECT_EQ(updater.cache["key2"].size(), 2);
//        EXPECT_EQ(getCachedValue(updater, "key2", "test_f21"), "test_v212"); // Entry updated
//        EXPECT_EQ(getCachedValue(updater, "key2", "test_f22"), "test_v22");

//        ASSERT_TRUE(updater.m_table->hget("key2", "test_f21", recv_val)); // Check in DB
//        EXPECT_EQ(recv_val, "test_v212");
//        ASSERT_TRUE(updater.m_table->hget("key2", "test_f22", recv_val));
//        EXPECT_EQ(recv_val, "test_v22");

//        // Key1 is not written yet
//        ASSERT_FALSE(updater.m_table->hget("key1", "test_f21", recv_val));

//        updater.destroy("key2")
//               .write("key2")
//               .build("key1", "test_f2", "test_v22")
//               .write("key1")
//               .write({
//                      "key3",
//                      SET_COMMAND,
//                      {
//                             { "test_f3", "test_v3" },
//                      }
//               })
//               .write({
//                      "key4",
//                      SET_COMMAND,
//                      {
//                             { "test_f4", "test_v4" },
//                      }
//               });

//        // Key2 is deleted from cache and DB
//        EXPECT_EQ(updater.cache["key2"].size(), 0);
//        ASSERT_FALSE(updater.m_table->hget("key2", "test_f21", recv_val));

//        ASSERT_TRUE(updater.m_table->hget("key1", "test_f", recv_val));
//        EXPECT_EQ(recv_val, "test_v");

//        ASSERT_TRUE(updater.m_table->hget("key1", "test_f2", recv_val));
//        EXPECT_EQ(recv_val, "test_v22");

//        EXPECT_EQ(updater.cache["key3"].size(), 1);
//        ASSERT_TRUE(updater.m_table->hget("key3", "test_f3", recv_val));
//        EXPECT_EQ(recv_val, "test_v3"); // Updated to DB

//        EXPECT_EQ(updater.cache["key4"].size(), 1);
//        EXPECT_EQ(getCachedValue(updater, "key4", "test_f4"), "test_v4");
//        ASSERT_FALSE(updater.m_table->hget("key4", "test_f3", recv_val));
//     }

// //     TEST(EniInfoTest, testEniInfo)
// //     {
// //        swss::IpPrefix vip("1.1.1.1/32");
// //        EniInfo eni1(string("aa:bb:cc:dd:ee:ff"), vip, string("vnet1"), nullptr);
// //        EniInfo eni2(string("aa:bb:cc:dd:ee:FF"), vip, string("vnet1"), nullptr);
// //        EniInfo eni3(string("aa:bb:cc:dd:ee:ee"), vip, string("vnet2"), nullptr);
// //        EXPECT_EQ(eni1, eni2);
// //        EXPECT_NE(eni1, eni3);
// //        EXPECT_NE(eni2, eni3);
// //     }
// }