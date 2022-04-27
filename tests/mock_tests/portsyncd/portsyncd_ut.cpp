#include "gtest/gtest.h"
#include "../mock_table.h"
#define private public 
#include "linksync.h"
#undef private

TEST(LinkSyncInitialization, test_initialization)
{
    ASSERT_EQ(0, 0);
}